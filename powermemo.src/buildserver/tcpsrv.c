/* vi: set ts=4 sw=4: */
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SERVER_PORT 5000
#define MAGIC 0x12508923
#define KPROBE 1
#define UPROBE 2
#define RESPONSE_OK     3
#define RESPONSE_FAIL   4

#define MAX_CMD_LEN 128

struct probe_info {
    unsigned long magic;
    unsigned short type;
    unsigned short length;
    char data[10240];
};

typedef struct ptr_list {
	char *function;
	struct ptr_list *next;
} PTR_LIST;

PTR_LIST *head = NULL;

static struct probe_info probe;

void insert_head(char *function)
{
	PTR_LIST *t;

	t = (PTR_LIST *)malloc(sizeof(PTR_LIST));
	t->function = (char *)malloc(strlen(function)*4/4 + 4);
	strcpy(t->function, function);
	t->next = head;
	head = t;
}
void visit()
{
	PTR_LIST *p;

	p = head;
	while (p != NULL) {
		printf("function name: %s\n", p->function); 
		p = p->next;
	}
}
void freeall()
{
	PTR_LIST *p;
	PTR_LIST *t;

	p = head;
	while (p != NULL) {
		t = p;
		printf("function name: %s\n", p->function); 
		p = p->next;
		free(t->function);
		free(t);
	}
	head = NULL;
}

/* This function reports the error and 
 * exits back to the shell
 */
static void bail(const char *on_what) {
	if (errno != 0)	{
		fputs(strerror(errno), stderr);
		fputs(": ", stderr);
	}
	fputs(on_what, stderr);
	fputc('\n', stderr);
	exit(1);
}

char * strtok_rr(char *string, const char *seps, char **context)
{
   char *head;  /* start of word */
	char *tail;  /* end of word */

	/* If we're starting up, initialize context */
	if (string) {
		*context = string;
	}

	/* Get potential start of this next word */
	head = *context;
	if (head == NULL) {
		return NULL;
	}

	/* Skip any leading separators */
	while (*head && strchr(seps, *head)) {
		head++;
	}

	/* Did we hit the end? */
	if (*head == 0) {
		/* Nothing left */
		*context = NULL;
		return NULL;
	}

	/* skip over word */
	tail = head;
	while (*tail && !strchr(seps, *tail)) {
		tail++;
	}

	/* Save head for next time in context */
	if (*tail == 0) {
		*context = NULL;
	}
	else {
		*tail = 0;
		tail++;
		*context = tail;
	}

	/* Return current word */
	return head;
}


/* Remove leading blanks */
char *ltrim(char *str)
{
	if(str == NULL)
		return NULL;
	while(*str == ' ' || *str == '\t')
		str++;
	return str;
}

/* Remove trailing blanks */
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

/* Remove leading and trailing blanks */
char *trim(char *str)
{
	return(ltrim(rtrim(str)));
}

int parse_data(char *data, char *file, char *func, int *line, int *start_line, int *end_line, char *app)
{
    char *str1, *str2, *token, *subtoken;
    char *saveptr1, *saveptr2;
    char *value;
    int j;

    for (j = 1, str1 = data; ; j++, str1 = NULL) {
        token = strtok_rr(str1, ";", &saveptr1);
        if (token == NULL)
            break;
        printf("%d: %s\n", j, token);

        for (str2 = token; ; str2 = NULL) {
            subtoken = strtok_rr(str2, ",", &saveptr2);
            if (subtoken == NULL)
                break;
            value = strsep(&subtoken, ":");
            if (value != NULL && subtoken != NULL)
            {
				if (strcasecmp(trim(value), "FILE_NAME") == 0)
					strcpy(file, trim(subtoken));
				else if (strcasecmp(trim(value), "LINE_NUMBER") == 0)
					*line = atoi(trim(subtoken));
				else if (strcasecmp(trim(value), "FUNCTION") == 0)
					strcpy(func, trim(subtoken));
				else if (strcasecmp(trim(value), "START_LINE_NUMBER") == 0)
					*start_line = atoi(trim(subtoken));
				else if (strcasecmp(trim(value), "END_LINE_NUMBER") == 0)
					*end_line = atoi(trim(subtoken));
				else if (strcasecmp(trim(value), "APPLICATION") == 0)
					strcpy(app, trim(subtoken));
                //printf("file:%s func:%s line:%d start_line:%d end_line:%d\n", file, func, *line, *start_line, *end_line);
            }
        }
    }
	
	return 1;
}

int parse_func(char *data, char *file)
{
    char *str1, *str2, *token, *subtoken;
    char *saveptr1, *saveptr2;
    char *value;
	char *ptr;
    int j;

    for (j = 1, str1 = data; ; j++, str1 = NULL) {
        token = strtok_rr(str1, ";", &saveptr1);
        if (token == NULL)
            break;
        printf("parse_func:%d: %s\n", j, token);

        for (str2 = token; ; str2 = NULL) {
            subtoken = strtok_rr(str2, ",", &saveptr2);
            if (subtoken == NULL)
                break;
            value = strsep(&subtoken, ":");
            if (value != NULL && subtoken != NULL)
            {
				if (strcmp(trim(value), "application") == 0)
					strcpy(file, trim(subtoken));
				else if (strcmp(trim(value), "function") == 0)
				{
					ptr = strchr(trim(subtoken), '(');
					if (ptr != NULL)
						*ptr = '\0';
					insert_head(trim(subtoken));
				}
				else
					printf("not supported keyword\n");
                //printf("file:%s func:%s line:%d start_line:%d end_line:%d\n", file, func, *line, *start_line, *end_line);
            }
        }
    }
	
	return 1;

}
int run_shell(char * buf, int size, const char * format, ...)
{
    FILE * fp;
    int i, c;
    char cmd[MAX_CMD_LEN];
    va_list marker;

    va_start(marker, format);
    vsnprintf(cmd, sizeof(cmd), format, marker);
    va_end(marker);

    fp = popen(cmd, "r");
    if (fp)
    {
        for (i = 0; i < size-1; i++)
        {
            c = fgetc(fp);
            if (c == EOF) break;
            buf[i] = (char)c;
        }
        buf[i] = '\0';
        pclose(fp);

        /* remove the last '\n' */
        i = strlen(buf);
        if (buf[i-1] == '\n') buf[i-1] = 0;
        return 0;
    }
    buf[0] = 0;
    return -1;
}


char *probe_data = NULL;
char bigbuffer[10240];
int main(int argc, char *argv[]) {
	char *srvr_addr = NULL;
	int srvr_port = SERVER_PORT;
	struct sockaddr_in adr_srvr;
	struct sockaddr_in adr_clnt;
	int len_inet;
	int z, s, c, n, i, ret;
	time_t td;
	char dtbuf[128];
	int length = 0;
	int line = 0;
	int start_line = 0;
	int end_line = 0;
	int type = 0;
	char filename[32];
	char funcname[32];
	char startaddr[32];
	char endaddr[32];
	char addrcmd[256];
	char *cmd_buf;
	int total_length = 0;
	unsigned short image_type = 0;
	char image[32];

	if (argc >= 2) {
		srvr_addr = argv[1];
	} else {
		srvr_addr = "127.0.0.1";
	}

	if (argc >= 3)
		srvr_port = atoi(argv[2]);

	/* create socekt service */
	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == -1)
		bail("socket()");

	printf("srv addr %s srv port %d\n", srvr_addr, srvr_port);
	memset(&adr_srvr, 0, sizeof(adr_srvr));
	adr_srvr.sin_family = AF_INET;
	adr_srvr.sin_port = htons(srvr_port);

	if (strcmp(srvr_addr, "*") != 0) {
		adr_srvr.sin_addr.s_addr = inet_addr(srvr_addr);
		if (adr_srvr.sin_addr.s_addr == INADDR_NONE)
			bail("bad address.");
	} else {
		adr_srvr.sin_addr.s_addr = INADDR_ANY;
	}

	len_inet = sizeof(adr_srvr);
	z = bind(s, (struct sockaddr *)&adr_srvr, len_inet);
	if (z == -1)
		bail("bind(2)");

	z = listen(s, 10);

	if (z == -1) 
		bail("listen(2)");

	//(void) signal(SIGCHLD, reaper);

	/* handle socket service */
    cmd_buf=malloc(1024);

    if (cmd_buf == NULL) {
        printf("allocate command output fail\n");
        exit(EXIT_FAILURE);
    }

	for (;;) {

		line = 0;
		start_line = 0;
		end_line = 0;
		len_inet = sizeof(adr_clnt);
		c = accept(s, (struct sockaddr *)&adr_clnt, &len_inet);

		if (c < 0) {
			if (errno == EINTR)
				continue;
			printf("accept: error %d\n", c);
		}

		if (c == -1)
			bail("accept(2)");
		
		while (ret = read(c, &probe, sizeof(struct probe_info))){
			printf("receive %d bytes from client =>\n", ret);
			printf("magic: %x\n", ntohl(probe.magic));			
			printf("type: %d\n", ntohs(probe.type));
			printf("length: %d\n", ntohs(probe.length));
			image_type = ntohs(probe.type);
			length = ntohs(probe.length);
			
			for (i = 0; i < length; i++)
				printf("%c", probe.data[i]);
			printf("\n");
			probe.data[length] = 0;

			if (image_type == 3) {
				parse_func(probe.data, filename);
				visit();
			} else {
				parse_data(probe.data, filename, funcname, &line, &start_line, &end_line, image);
			}
			if (image_type == 3)
			{
				PTR_LIST *p;

				p = head;
				i = 0;
				while (p != NULL) {
        			printf("function name: %s\n", p->function);
					sprintf(addrcmd, "./func2addr -s %s -f %s -e %s -a %s.asm\n", filename, p->function, filename, filename);
                	printf("cmd is %s\n", addrcmd);
                	run_shell(cmd_buf, 1024, "%s", addrcmd);
                	printf("The result is %s\n", cmd_buf);
					p = p->next;
					if (i == 0) {
						sprintf(bigbuffer + i, "%s", cmd_buf);
						i = strlen(cmd_buf);
					}
					else {
						sprintf(bigbuffer + i, "@%s", cmd_buf);
						i += strlen(cmd_buf) + 1;
					}
				}
				printf("haha %s\n", bigbuffer);
				/* prepare the probe information */
				memset(&probe, 0, sizeof(struct probe_info));
    			probe.magic = htonl(MAGIC);
    			probe.type = htons(RESPONSE_OK);
				memcpy(probe.data, bigbuffer, strlen(bigbuffer));
				probe.length = htons(strlen(bigbuffer));
				total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + strlen(bigbuffer);
				write(c, &probe, total_length);
				freeall();
				memset(&probe, 0, sizeof(struct probe_info));
				continue;			
			}	
			/* */
			if (image_type == 2) 
				strcpy(image, "vmlinux");
			
			if (line != 0)
			{
				printf("line is not zero\n");
				//sprintf(addrcmd, "./line2addrver2 -s %s -f %s -l %d -e %s -a %s.asm\n", filename, funcname, line, image, image);
				sprintf(addrcmd, "./line2addrver2 -f %s -l %d -e %s -a %s.asm\n", funcname, line, image, image);
				printf("cmd is %s\n", addrcmd);
            	run_shell(cmd_buf, 1024, "%s", addrcmd);
            	printf("The result is %s\n", cmd_buf);
				type = 0;
			}
			else if (start_line != 0 && end_line != 0)
			{
				printf("start line not zero end line not zero\n");
				type = 1;
				//sprintf(addrcmd, "./line2addrver2 -s %s -f %s -l %d -e %s -a %s.asm\n", filename, funcname, start_line, image, image);			
				sprintf(addrcmd, "./line2addrver2 -f %s -l %d -e %s -a %s.asm\n", funcname, start_line, image, image);
				printf("cmd is %s\n", addrcmd);
				run_shell(cmd_buf, 1024, "%s", addrcmd);		
				printf("The result for start is %s\n", cmd_buf);
				strcpy(startaddr, cmd_buf);

                //sprintf(addrcmd, "./line2addrver2 -s %s -f %s -l %d -e %s -a %s.asm\n", filename, funcname, end_line, image, image);
				sprintf(addrcmd, "./line2addrver2 -f %s -l %d -e %s -a %s.asm\n", funcname, end_line, image, image);
                printf("cmd is %s\n", addrcmd);
                run_shell(cmd_buf, 1024, "%s", addrcmd);
                printf("The result for end is %s\n", cmd_buf);
				strcpy(endaddr, cmd_buf);
			}
    		/* prepare the probe information */
			memset(&probe, 0, sizeof(struct probe_info));
    		probe.magic = htonl(MAGIC);
    		probe.type = htons(RESPONSE_OK);
			if (type == 0)
			{
				printf("type = 0 %s\n", cmd_buf);
				if (strncmp(cmd_buf, "address:", 8) == 0) {
					probe_data = cmd_buf;
    				memcpy(probe.data, probe_data, strlen(probe_data));
    				probe.length = htons(strlen(probe_data));
				}else {
					strcpy(cmd_buf, "address:NULL");
					probe_data = cmd_buf;
					memcpy(probe.data, probe_data, strlen(probe_data));
					probe.length = htons(strlen(probe_data)); 
				}
			}
			else if (type == 1)
			{
				char tmp_buf[1024];

				printf("type = 1\n");
				probe_data = tmp_buf;
				/* Get the start address start_address:80485955 */
                if (strncmp(startaddr, "address:", 8) == 0) {
					sprintf(probe_data, "start_address:%s", &startaddr[8]);
					probe.length = strlen(probe_data);
                }else {
                    memcpy(probe_data, "start_address:NULL", 18);
                    probe.length = 18;
                }

                if (strncmp(endaddr, "address:", 8) == 0) {
                    sprintf(probe_data + strlen(probe_data), ";end_address:%s", &endaddr[8]);
                    probe.length += strlen(probe_data);
                }else {
                    memcpy(probe_data + strlen(probe_data), ";end_address:NULL", 17);
                    probe.length += 17;
                }
				printf("probe_data=%s\n", probe_data);
				memcpy(probe.data, probe_data, strlen(probe_data));
                probe.length = htons(strlen(probe_data));
			}
			printf("haha1\n");
    		total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + strlen(probe_data);
			//total_length = 10;
			printf("haha %d\n", total_length);
    		write(c, &probe, total_length);
			printf("haha 2\n");
			memset(&probe, 0, sizeof(struct probe_info));
		}
		#if 0
		switch (fork()) {
		case 0:/* child */
			(void) close(msock);
			exit(TCPechod(ssock));
		default:/* parent */
			(void) close(ssock);
		break;
		case -1: errexit("fork: %s\n", sys_errlist[errno]);
		}
		#endif	
		close(c);
	}

	return 0;
}


