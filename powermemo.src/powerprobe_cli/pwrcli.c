#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SRV_PORT 5000
#define MAGIC 0x12508923

#define REGISTER_KPROBE					1
#define UNREGISTER_KPROBE				2
#define REGISTER_UPROBE					3
#define UNREGISTER_UPROBE				4
#define REGISTER_SCHEDULE				5
#define UNREGISTER_SCHEDULE				6
#define REGISTER_DUAL_KPROBE			7
#define UNREGISTER_DUAL_KPROBE			8
#define REGISTER_DUAL_UPROBE			9
#define UNREGISTER_DUAL_UPROBE			10
#define REGISTER_FUNCTION_KPROBE		11
#define UNREGISTER_FUNCTION_KPROBE		12
#define REGISTER_FUNCTION_UPROBE		13
#define UNREGISTER_FUNCTION_UPROBE		14

#define GET_MEASURE_RESULT 				20
#define GET_SCHEDULE_MEASURE_RESULT		21
#define START_FUNCTION_MEASUREMENT		22
#define STOP_FUNCTION_MEASUREMENT		23
#define REGISTER_START_ALL				24
#define REGISTER_STOP_ALL				25


//char probe_data[] = "FILE_NAME: sched.c;FUNCTION: schedule;LINE_NUMBER: 660;ADDRESS: 0xc0485ff8;ACTION: 1";
char probe_data[1000];

char power_data[5000];
struct probe_info {
	unsigned long magic;
	unsigned short type;
	unsigned short length;
	char data[1024];
};

static struct probe_info probe;

static void bail(const char *on_what)
{
	fputs(strerror(errno), stderr);
	fputs(": ", stderr);
	fputs(on_what, stderr);
	fputc('\n', stderr);
	exit(1);
}
int parse_hex(char *str, unsigned long *value)
{
    char *buf_ptr;
    char c;

    buf_ptr = str ;
    *value = 0 ;

    while ((c = *buf_ptr++) != '\0')
    /* check if input char is hex symbol? */
    if(isdigit(c))
    {
        /* convert char symbol to upper case */
        c = (char) toupper((int)c );
        /* 'A' ~ 'F' */
        if ((c -= '0') > 9 )
            c -= ('A'-'9'-1); /* convert the hex symbol to hex number */
            *value = 16 * (*value) + c;
        }
        else
        {
            if ( c != '\0' )
                return 0;
            break ;
        } /* end of if-else */
        return 1 ;
}  /* End of parse_hex()*/

/* 
 * string library 
 */

int isEmpty(const char *s)
{
	if(s == NULL)
		return 1;
	if(*s == 0)
		return 1;
	return 0;
}

char *ltrim(char *str)
{
	if(str == NULL)
		return NULL;
	while(*str == ' ' || *str == '\t')
		str++;
	return str;
}

char *rtrim(char *str)
{
	char *index;
	
	if(str == NULL)
		return NULL;
	if(*str == 0)
		return str;
	index = str + strlen(str) - 1;
	while(*index == ' ' || *index == '\t')
	{
		*index = 0;
		if(index > str)
			index--;
	}
	return str;
}
char *trim(char *str)
{
	return(ltrim(rtrim(str)));
}
char *strsep(char **stringp, const char *delim)
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
}

/* Extract token from string and remove leading and trailing blanks */
char *strsep_t(char **stringp, const char *delim)
{
	return trim(strsep(stringp, delim));
}

char *get_line(char **stringp)
{
	char *line;

	if(*stringp == NULL)
		return NULL;
	line = strsep(stringp, "\n");
	if(line == NULL)
		return NULL;
	line = strsep(&line, "\r");
	
	return trim(line);
}
int isHexDigit(char x)
{
    if ((x >= 0x30) && (x <= 0x39))
        return 1;
    else if ((x >= 0x41) && (x <=0x46))
        return 1;
    else if ((x >= 0x61) && (x <= 0x66))
        return 1;
    
    return 0;
}
int isAddress(char *str)
{
	char *ch=NULL;

	ch=str;
	while (ch && *ch != 0)
		if (isHexDigit(*ch++) == 0)
			return 0;
	return 1;
}

char *get_FuncName(char **str)
{
	char *tmp_str;

	tmp_str=strsep(str, "<");
	if (tmp_str == NULL)
		return NULL;
	tmp_str=strsep(str, ">");
	//printf("FuncName=%s\n", tmp_str);
	return tmp_str;
}

#define TASK_COMM_LEN 16
struct processor_u {
	unsigned long pid;
	char comm[TASK_COMM_LEN];
	unsigned long t_entry; /* entry time of the time slice */
	unsigned long t_exit; /* exit time of the time slice */
	unsigned long delta;
	char func_name[32];
};

unsigned short parse_type(char *type)
{

	if (!type)
		return 0;

	if (strcmp(type, "regk") == 0)
		return REGISTER_KPROBE;
	else if (strcmp(type, "unregk") == 0)
		return UNREGISTER_KPROBE;
	else if (strcmp(type, "regu") == 0)
		return REGISTER_UPROBE;
	else if (strcmp(type, "unregu") == 0)
		return UNREGISTER_UPROBE;
	else if (strcmp(type, "regdk") == 0)
		return REGISTER_DUAL_KPROBE;
	else if (strcmp(type, "unregdk") == 0)
		return UNREGISTER_DUAL_KPROBE;
	else if (strcmp(type, "regdu") == 0)
		return REGISTER_DUAL_UPROBE;
	else if (strcmp(type, "unregdu") == 0)
		return UNREGISTER_DUAL_UPROBE;
	else if (strcmp(type, "regfk") == 0)
		return REGISTER_FUNCTION_KPROBE;
	else if (strcmp(type, "unregfk") == 0)
		return UNREGISTER_FUNCTION_KPROBE;
	else if (strcmp(type, "regfu") == 0)
		return REGISTER_FUNCTION_UPROBE;
	else if (strcmp(type, "unregfu") == 0)
		return UNREGISTER_FUNCTION_UPROBE;
	else 
		printf("not supported command\n");//pwrcli_usage();

	return 0;	
}
int regnum = 0;
int main(int argc, char *argv[]) {
	int z, i;
	char *srvr_addr = NULL;
	unsigned int srvr_port = htons(SRV_PORT);
	struct sockaddr_in adr_srvr;
	int len_inet, total_length, length;
	int s;
	struct servent *sp;
	char dtbuf[128];
	unsigned long addr;
	int header_len = 0;
	struct processor_u *pru = NULL;
	char *p = NULL;
	char *buf = NULL;
	unsigned short type = 0;
	int fdsrc;
	char *str = NULL, *line = NULL, *fun = NULL;
	struct stat filestat;
	int numbytes, len, first_time = 0;
	char filename[32];
	char application[32];
	char function[32];
	char address[32];


	strcpy(application, "default");
	strcpy(filename, "default");
	strcpy(function, "default");
	strcpy(address, "0x00000000");
	if (argc >= 2) {
		srvr_addr = argv[1];
	} else {
		srvr_addr = "127.0.0.1";
	}

	if (argc == 3)
		srvr_port = htons(atoi(argv[2]));

	memset(&adr_srvr, 0, sizeof(adr_srvr));
	adr_srvr.sin_family = AF_INET;
	adr_srvr.sin_port = srvr_port;
	adr_srvr.sin_addr.s_addr = inet_addr(srvr_addr);

	printf("tcp client: %s %d\n", srvr_addr, srvr_port);
	if (adr_srvr.sin_addr.s_addr == INADDR_NONE)
		bail("bad address.");
	
	len_inet = sizeof(adr_srvr);

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1)
		bail("socket()");

	z = connect(s, &adr_srvr, len_inet);
	if (z == -1)
		bail("connect(2)");

	if (argc == 4)
	{
		printf("command %s file %s\n", argv[2], argv[3]);
		type = parse_type(argv[2]);
		probe.type = htons(type);
		printf("Type = %d Probe type = %d\n", type, probe.type);
		strcpy(filename, argv[3]);
		
			
		/* prepare the probe information */
		if((fdsrc = open(argv[3], O_RDONLY)) < 0) {
			perror("open fdsrc");
			exit(EXIT_FAILURE);
		}
		
		fstat(fdsrc, &filestat);	
		buf = malloc(filestat.st_size);
		
		if (buf == NULL){
			printf("allocate memory fail\n");
			exit(EXIT_FAILURE);
		}
		
		while((numbytes = read(fdsrc, buf, filestat.st_size)) != 0) {

			str=buf;

			while (1) {
				line=get_line(&str);
				
				if (line == 0)
					break;

				if (line && (*line == 0 || *line=='#'))
					continue;

				//if (!(regnum++ >= 2000 && regnum < 3000))
				//	continue;
				
				fun = strsep_t(&line, ",");
				
				if (fun == NULL || line == NULL)
					break;

				strcpy(function, fun);
				strcpy(address, line);

				fun = filename;
				p = strsep_t(&fun, ".");

				if (p != NULL)
					strcpy(application, p);

				printf("fun: %s addr: %s app: %s\n", function, address, application);
				sprintf(probe_data, "FILE_NAME:%s;APPLICATION:%s;FUNCTION:%s;ADDRESS:%s;START_ADDRESS:%s;END_ADDRESS:%s;LINE_NUMBER:0;ACTION:0", 
							filename, application, function, address, address, address);
					
				probe.magic = htonl(MAGIC);
				probe.type = htons(type);
				memcpy(probe.data, probe_data, strlen(probe_data));
				probe.length = htons(strlen(probe_data));
				
				total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + strlen(probe_data);
				
				write(s, &probe, total_length); 
				
				memset(&probe, 0, sizeof(struct probe_info));
				
				header_len = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length);
				z = read(s, &probe, header_len);
				printf("magic = %x type = %d length = %d\n", ntohl(probe.magic), ntohs(probe.type), ntohs(probe.length));
				
				p = power_data;
				i = 0;
				while (z = read(s, p, ntohs(probe.length)))
				{
					p+=z;
					i+=z;
					printf("iii=%d %d\n", i, ntohs(probe.length));
					if (i >= ntohs(probe.length)) break;
					for (i = 0; i < ntohs(probe.length); i++)
						printf("%02x ", power_data[i]&0xff);
					printf("\n");
				}
			}
		}
		close(fdsrc);
		close(s);
		return 0;
	}		
 
	/* prepare the probe information */
	probe.magic = htonl(MAGIC);		
	probe.type = htons(UNREGISTER_KPROBE);
	//probe.type = htons(REGISTER_KPROBE);
	memcpy(probe.data, probe_data, strlen(probe_data));
	probe.length = htons(strlen(probe_data));

	total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + strlen(probe_data);

	write(s, &probe, total_length); 

	memset(&probe, 0, sizeof(struct probe_info));

	header_len = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length);
	z = read(s, &probe, header_len);
	printf("magic = %x type = %d length = %d\n", ntohl(probe.magic), ntohs(probe.type), ntohs(probe.length));
	
	p = power_data;
	i = 0;
	while (z = read(s, p, ntohs(probe.length)))
	{
		p+=z;
		i+=z;
		printf("iii=%d %d\n", i, ntohs(probe.length));
		if (i >= ntohs(probe.length)) break;
		for (i = 0; i < ntohs(probe.length); i++)
			printf("%02x ", power_data[i]&0xff);
		printf("\n");
	} 
	#if 0
	i = ntohs(probe.length); 
	pru = (struct processor_u *)power_data;
	printf("i=%d\n", i);
	while (i > 0)
	{
		i = i - sizeof(struct processor_u);
		printf("pid:%d task name: %s entry:0x%x exit:0x%x delta:%d func_name:%s\n", 
					pru->pid, pru->comm, pru->t_entry, pru->t_exit, pru->delta, pru->func_name);
		pru++;
	}
	#endif
error:
	close(s);

	return 0;	
}
