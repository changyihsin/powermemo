/* vi: set ts=4 sw=4: */
/****************************************************************************/
/*      POWERAGENT.C                                                        */
/*                                                                          */
/* DESCRIPTION                                                              */
/*                                                                          */
/*                                                                          */
/* AUTHOR: Vincent Chang                                               		*/
/*                                                                          */
/*                                                                          */
/* (C) Copyright 2011 NCTU.                                    				*/
/*     This software is the property of Alphanetworks and shall not         */
/*     be reproduced distributed and copied without the permission.     	*/
/*                                                                          */
/****************************************************************************/
/* ============================= */
/* Includes                      */
/* ============================= */

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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "power.h"

#define SERVER_PORT 5000
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



#define RESPONSE_OK     		200
#define RESPONSE_FAIL   		201

#define MAX_CMD_LEN 128

#define DEVNAME "/dev/power"

#define DEBUG 1
#define TASK_COMM_LEN 	16
#define LOG_BUF_SIZE 10240
#define MAX_DATA_SIZE LOG_BUF_SIZE

struct probe_info {
  unsigned long magic;
  unsigned short type;
  unsigned short length;
  char data[MAX_DATA_SIZE];
};

struct processor_u {
	unsigned long pid;
	char comm[TASK_COMM_LEN];
	unsigned long t_entry; /* entry time of the time slice */
	unsigned long t_exit; /* exit time of the time slice */
	unsigned long delta;
	char func_name[32];	
};

static struct probe_info probe;

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

int parse_hex(char *str, unsigned long *value)
{
	char *buf_ptr;
	char c;

	/* skip 0x */
	if (strncmp(str, "0x", 2) == 0)
		str +=2;
	
	buf_ptr = str ;
	*value = 0 ;

	while ((c = *buf_ptr++) != '\0')
	{
		/* check if input char is hex symbol? */
		if(isxdigit(c)) 
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
	}	
	return 1 ;
}  /* End of parse_hex()*/

void dump_data(struct power_cmd *data)
{
	printf("Filename: %s\n", data->filename);
	printf("Function: %s\n", data->function);
	printf("Application: %s\n", data->image);
	printf("line: %d\n", data->line);
	printf("start_line: %d\n", data->start_line);
	printf("end_line: %d\n", data->end_line);
	printf("address: 0x%x\n", data->address);
	printf("start_addr: 0x%x\n", data->start_address);
	printf("end_addr: 0x%x\n", data->end_address);
	printf("Action: %d\n", data->action);
}
/* 
 * The format will be 
 * FILE_NAME: file;LINE_NUMBER: line number;FUNCTION: function name;ADDRESS: address;ACTION: 1
 */
int parse_data(char *input, struct power_cmd *data)

{
    char *str1, *str2, *token, *subtoken;
    char *saveptr1, *saveptr2;
    char *value;
    int j;

    for (j = 1, str1 = input; ; j++, str1 = NULL) {
        token = strtok_rr(str1, ";", &saveptr1);
        if (token == NULL)
            break;

		#if DEBUG 
        printf("%d: %s\n", j, token);
		#endif

        for (str2 = token; ; str2 = NULL) {
            subtoken = strtok_rr(str2, ",", &saveptr2);
            if (subtoken == NULL)
                break;
            value = strsep(&subtoken, ":");
            if (value != NULL && subtoken != NULL)
            {
				if (strcasecmp(trim(value), "FILE_NAME") == 0)
					strcpy(data->filename, trim(subtoken));
				else if (strcasecmp(trim(value), "LINE_NUMBER") == 0)
					data->line= atoi(trim(subtoken));
				else if (strcasecmp(trim(value), "FUNCTION") == 0)
					strcpy(data->function, trim(subtoken));
				else if (strcasecmp(trim(value), "ADDRESS") == 0)
				{	
					parse_hex(trim(subtoken), (unsigned long *)&data->address); 
				}
				else if (strcasecmp(trim(value), "START_ADDRESS") == 0)
				{	
					parse_hex(trim(subtoken), (unsigned long *)&data->start_address); 
				}
				else if (strcasecmp(trim(value), "END_ADDRESS") == 0)
				{	
					parse_hex(trim(subtoken), (unsigned long *)&data->end_address); 
				}	
				else if (strcasecmp(trim(value), "ACTION") == 0)
				{
					data->action= atoi(trim(subtoken));
				}
				else if (strcasecmp(trim(value), "APPLICATION") == 0)
				{
					strcpy(data->image, trim(subtoken));
				}
				else if (strcasecmp(trim(value), "START_LINE_NUMBER") == 0)
				{
					data->start_line = atoi(trim(subtoken));
				}
				else if (strcasecmp(trim(value), "END_LINE_NUMBER") == 0)
				{
					data->end_line = atoi(trim(subtoken));
				}
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
int main(int argc, char *argv[]) {
	char *srvr_addr = NULL;
	int srvr_port = SERVER_PORT;
	struct sockaddr_in adr_srvr;
	struct sockaddr_in adr_clnt;
	int len_inet;
	int z, s, c, ret;
	int length = 0;
	int line = 0;
	char filename[32];
	char funcname[32];
	char image[32];
	char *cmd_buf;
	unsigned short type = 0;
	unsigned long addr = 0;
	unsigned long start_addr = 0;
	unsigned long end_addr = 0; 
	int action = 0;
	int total_length = 0;
	int fd = 0 ;
	struct power_cmd data;
	struct processor_u *pru = NULL;
	int i = 0;
	char *ptest = NULL;
	
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

	fd = open(DEVNAME, O_RDWR);

	if (fd < 0) {
		printf("can't open power drvier\n");
		exit(EXIT_FAILURE);
	}

	for (;;) {

		len_inet = sizeof(adr_clnt);
		c = accept(s, (struct sockaddr *)&adr_clnt, &len_inet);

		if (c < 0) {
			if (errno == EINTR)
				continue;
			printf("accept: error %d\n", c);
		}

		if (c == -1)
			bail("accept(2)");
		
		while ((ret = read(c, &probe, sizeof(struct probe_info))) > 0){

			#if DEBUG
			printf("receive %d bytes from client =>\n", ret);
			printf("magic: %x\n", ntohl(probe.magic));			
			printf("type: %d\n", ntohs(probe.type));
			printf("length: %d\n", ntohs(probe.length));
			#endif
			type = ntohs(probe.type);
			length = ntohs(probe.length);

			//for (i = 0; i < length; i++)
			//	printf("%c", probe.data[i]);
			//printf("\n");
			memset(&data, 0, sizeof(data));
			parse_data(probe.data, &data);
			dump_data(&data);
			switch (type)
			{
				case REGISTER_KPROBE:
					//printf("register kprobe\n");
					ioctl(fd, REGISTER_KPROBE_CMD, &data);
					break;
				case UNREGISTER_KPROBE:
					//printf("unregister kprobe\n");
					ioctl(fd, UNREGISTER_KPROBE_CMD, &data);
					break;
				case REGISTER_UPROBE:
					//printf("register uprobe\n");
					ioctl(fd, REGISTER_UPROBE_CMD, &data);
					break;
				case UNREGISTER_UPROBE:
					//printf("unregister uprobe\n");
					ioctl(fd, UNREGISTER_UPROBE_CMD, &data);
					break;
				case REGISTER_SCHEDULE:
					printf("register schedule\n");
					system("echo 1 > /debug/tracing/tracing_enabled");
					//ioctl(fd, REGISTER_SCHEDULE_CMD, NULL);
					break;
				case UNREGISTER_SCHEDULE:
					printf("unregister schedule\n");
					system("echo 0 > /debug/tracing/tracing_enabled");
					//ioctl(fd, UNREGISTER_SCHEDULE_CMD, NULL);
					break;					
				case REGISTER_DUAL_KPROBE:
					//printf("register dual kprobe\n");
					ioctl(fd, REGISTER_DUAL_KPROBE_CMD, &data);
					break;
				case UNREGISTER_DUAL_KPROBE:
					//printf("unregister dual kprobe\n");
					ioctl(fd, UNREGISTER_DUAL_KPROBE_CMD, &data);
					break;
				case REGISTER_DUAL_UPROBE:
					//printf("register dual uprobe\n");
					ioctl(fd, REGISTER_DUAL_UPROBE_CMD, &data);
					break;
				case UNREGISTER_DUAL_UPROBE:
					//printf("unregister dual uprobe\n");
					ioctl(fd, UNREGISTER_DUAL_UPROBE_CMD, &data);
					break;
				case REGISTER_FUNCTION_KPROBE:
					//printf("register kernel function\n");
					ioctl(fd, REGISTER_FUNCTION_KPROBE_CMD, &data);
					break;
				case UNREGISTER_FUNCTION_KPROBE:
					//printf("unregister kernel function\n");
					ioctl(fd, UNREGISTER_FUNCTION_KPROBE_CMD, &data);
					break;
				case REGISTER_FUNCTION_UPROBE:
					//printf("register user function\n");
					ioctl(fd, REGISTER_FUNCTION_UPROBE_CMD, &data);
					break;
				case UNREGISTER_FUNCTION_UPROBE:
					//printf("unregister user function\n");
					ioctl(fd, UNREGISTER_FUNCTION_UPROBE_CMD, &data);
					break;
				case GET_MEASURE_RESULT:
				#if 1
				{
					int fd = 0, count = 0;
					
					memset(&probe, 0, sizeof(struct probe_info));
					system("cat /proc/powerdbg > /tmp/fun_result");
					fd = open("/tmp/fun_result", O_RDWR);
					count = read(fd, probe.data, MAX_DATA_SIZE);
					printf("fd =%d count = %d\n", fd, count);
					probe.magic = htonl(MAGIC);
					probe.type = htons(RESPONSE_OK);
					probe.length = htons(count);					
					total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + count;
					printf("total length = %d\n", total_length);
					count = write(c, &probe, total_length);
					printf("w count %d\n", count);
					system("echo clean > /proc/powerdbg");
					continue;
				}
				#else
					printf("get measure result\n");
					memset(&probe, 0, sizeof(struct probe_info));
					length = ioctl(fd, GET_MEASURE_RESULT_CMD, probe.data);
					probe.magic = htonl(MAGIC);
					probe.type = htons(RESPONSE_OK);
					probe.length = htons(length);					
					total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + length;										

					i = length;					
					pru = (struct processor_u *)probe.data;
					while (i > 0) {
						i = i - sizeof(struct processor_u);
						printf("pid:%d task name: %s entry:0x%x exit:0x%x delta:%d func_name:%s\n",
									pru->pid, pru->comm, pru->t_entry, pru->t_exit, pru->delta, pru->func_name);
						pru++;
					}
					write(c, &probe, total_length);
					continue;
				#endif
				case GET_SCHEDULE_MEASURE_RESULT:
				{
					int fd = 0, count = 0;
					
					memset(&probe, 0, sizeof(struct probe_info));
					system("cat /debug/tracing/latency_trace > /tmp/sched_result");
					fd = open("/tmp/sched_result", O_RDWR);
					count = read(fd, probe.data, MAX_DATA_SIZE);
					printf("fd =%d count = %d\n", fd, count);
					probe.magic = htonl(MAGIC);
					probe.type = htons(RESPONSE_OK);
					probe.length = htons(count);					
					total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length) + count;
					printf("total length = %d\n", total_length);
					count = write(c, &probe, total_length);
					printf("w count %d\n", count);
					
					continue;
				}
				case START_FUNCTION_MEASUREMENT:
					printf("start function power measurement\n");
					system("echo start > /proc/powerdbg");
					break;
				case STOP_FUNCTION_MEASUREMENT:
					printf("stop function power measurement\n");
					system("echo stop > /proc/powerdbg");
					break;
				case REGISTER_START_ALL:
					printf("start system measurement\n");
					//system("echo 1 > /debug/tracing/tracing_enabled");
					system("echo start > /proc/powerdbg");
					break;
				case REGISTER_STOP_ALL:
					printf("stop system measurement\n");
					//system("echo 0 > /debug/tracing/tracing_enabled");
					system("echo stop > /proc/powerdbg");
					break;
				default:
					printf("receive undefined type\n");
					break;;
			}
    		/* prepare the reply message  */
			memset(&probe, 0, sizeof(struct probe_info));
    		probe.magic = htonl(MAGIC);
    		probe.type = htons(RESPONSE_OK);
    		probe.length = 0;
    		total_length = sizeof(probe.magic) + sizeof(probe.type) + sizeof(probe.length);
    		write(c, &probe, total_length);
		}
		close(c);
	}

	return 0;
}


