
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/wait.h>

#include "protocol.h"
#include "protocol_util.h"

#include "runscript.h"

static int parsePrefix(struct pm_prefix* const pfx_ptr);

static void do_QueryRequest(int type);
static void do_RunScript();
static int executeCommand(int type, char* name);
static void response_header(int type);
static inline void redirection(int src, int dst);

static void transmit(int fd);

static int server_socket_fd;

void waitForRequest(int sockfd)
{

	server_socket_fd = sockfd;

	while (1) {

		fprintf(stderr, "READ!!\n");

		struct pm_prefix pfx_buf;
		int ret = 0;
		int n = read(sockfd, &pfx_buf, sizeof(pfx_buf));

		fprintf(stderr, "read byte: %d\n", n);

		if ( n < 0 || n == 0 ) {
			perror("read");
			exit(EXIT_FAILURE);

		}

		fprintf(stderr, "[%d] [%c] [%d]\n", n, pfx_buf.sig, pfx_buf.type);

		ret = parsePrefix(&pfx_buf);

		printf("return value: %d\n", ret);

		if (ret < 0) {
			exit(EXIT_FAILURE);
		} else if (ret == 1) {
			return;
		}

	}

}


static int parsePrefix(struct pm_prefix* const pfx_ptr)
{
	fprintf(stderr, "parse\n");

	if (pfx_ptr->sig != 'M') {
		return -1;
	}

	switch (pfx_ptr->type) {
		case PROCESS_REQUEST:           /* Process Request*/
			do_QueryRequest(PROCESS_REQUEST);
			break;
		case CLASS_REQUEST:             /* Class Request */
			do_QueryRequest(CLASS_REQUEST);
			break;
		case METHOD_REQUEST:            /* Method Request */
			do_QueryRequest(METHOD_REQUEST);
			break;
		case END_SECTION:               /* End of Section */

			fprintf(stderr, "End section, return 1\n");
			return 1;
			break;
		case RUN_SCRIPT:                /* Run Script */
			do_RunScript();
			break;
		default:
			return -1;
			break;
	}


	return 0;
}


static void do_QueryRequest(int type)
{
	fprintf(stderr, "Query, type:%d\n", type);
	/* do some basic init */

	char *name = NULL;
	if (type == CLASS_REQUEST || type == METHOD_REQUEST) {
		unsigned int len;
		int n = read(server_socket_fd, &len, sizeof(len) );

		fprintf(stderr, "read size: [%d], len: [%d]\n", n, len);

		if (n < 0 || n == 0) {
			exit(EXIT_FAILURE);
		}

		name = malloc((len + 1) * sizeof(char));
		n = read (server_socket_fd, name, len);
		if (n < 0 || n == 0) {
			exit(EXIT_FAILURE);
		}

		name[n] = '\0';
		fprintf(stderr, "string:[%s]\n", name);
	}

	int pm_pipe[2];
	pipe(pm_pipe);

	pid_t pid = fork();

	if (pid < 0) {

		exit(EXIT_FAILURE);

	} else if (pid == 0) {

		close(server_socket_fd);
		close(pm_pipe[0]); /* read */
		redirection(pm_pipe[1], STDOUT_FILENO);

		int ret = executeCommand(type, name);

		fprintf(stderr, "ret: %d\n", ret);

		free(name);
		exit(ret);

	} else {

		close(pm_pipe[1]); /* write */

		fprintf(stderr,"wait %d\n", pid);
		int status;	
		//waitpid(pid, &status, WEXITED);
		wait(&status);
		fprintf(stderr,"over!\n");

		/* response header*/
		response_header(type);
		
		transmit(pm_pipe[0]);
	}



}

static inline void response_header(int type)
{
	struct pm_prefix pfx;
	pfx.sig = 'M';
	pfx.type = type;

	write(server_socket_fd, &pfx, sizeof(pfx));
}

static void transmit(int fd)
{
	fd_set readfds, rfds;

	char buffer[512];

	FD_ZERO(&readfds);
	FD_ZERO(&rfds);

	FD_SET(fd, &readfds);

	while (1) {
		memcpy(&rfds, &readfds, sizeof(readfds));

		if (select(FD_SETSIZE + 1, &rfds, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}

		if (FD_ISSET(fd, &rfds)) {

			int n = read(fd, buffer, sizeof(buffer));
			if (n < 0) {
				perror("read");
				exit(EXIT_FAILURE);
			} else if (n == 0) {
				printf("End of transmit\n");
				break;
			} else {
				int r = write(server_socket_fd, buffer, n);
				if (r < 0 || r != n) {
					perror("write");
					exit(EXIT_FAILURE);
				}
			}

		}
	}



}

static void do_RunScript()
{
	unsigned char packet_num = 0;;
	fprintf(stderr, "read pack num\n");
	int n = read(server_socket_fd, &packet_num, sizeof(packet_num));
	if (n < 0 || n == 0) {
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "count: %u\n", packet_num);

	int count = packet_num;
	while (count) {
		struct rs_packet_prefix rs_pfx;

		printf("read rs_pfx, sizeof: %u\n", sizeof(rs_pfx));
		n = read(server_socket_fd, &rs_pfx, sizeof(rs_pfx));
		if (n < 0 || n == 0) {
			exit(EXIT_FAILURE);
		}
		unsigned start = *(unsigned*)(&rs_pfx.start_time);
		unsigned end = *(unsigned*)(&rs_pfx.end_time);

		printf("s: %u, e: %u, cmd_length: %u\n", start, end, rs_pfx.cmd_length);

		char *rs_cmd = malloc((rs_pfx.cmd_length + 1) * sizeof(char)); 
		n = read(server_socket_fd, rs_cmd, rs_pfx.cmd_length);
		if (n < 0 || n == 0) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		rs_cmd[rs_pfx.cmd_length] = '\0';
		
		printf(" read byte: %d, rs_cmd: [%s]\n",n ,rs_cmd);

		printf("Add to run script storage\n");
		add_RunScript(start, end, rs_cmd);
	
		free(rs_cmd);
		--count;	
	}	

}



static int executeCommand(int type, char* name)
{
	int ret;
	const char pm_client_name[] = "/data/powermemo/talker";
	/* please change this file name to fit your env. ! */

	fprintf(stderr, "talker path: [%s]\n", pm_client_name);

	fprintf(stderr, "execute\n");

	if (type == PROCESS_REQUEST) {
		char* cmd[] = {"ps", (char*)0};
		ret = execv("/system/bin/ps", cmd);
	} else if (type == CLASS_REQUEST) {
		char* cmd[] = {"talker", "1", name, (char*)0};
		ret = execv(pm_client_name, cmd);
	}
	else if (type == METHOD_REQUEST) {
		char* cmd[] = {"talker", "2", name,(char*)0};
		ret = execv(pm_client_name, cmd);
	}

	return ret;

}


static inline void redirection(int src, int dst)
{
	close(dst);
	dup2(src, dst);
}




