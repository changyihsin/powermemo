


#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h> 

#include "protocol.h"
#include "protocol_util.h"

#include "client.h"

#include "runscript.h"

static void sig_chld_reaper(int signo);
static int triggerPowerMemo();
static void triggerRunScript(const char* cmd);

static int sockfd = 0;

int main(int argc, char* argv[])
{
	if (argc < 3) {
		fprintf(stderr, "Error: too few args!\n");
		fprintf(stderr, "Usage: ./pm_client ip port\n");
		exit(EXIT_FAILURE);
	}

	int server_port = atoi(argv[2]);
	sockfd = activeSocket(argv[1], server_port);

	waitForRequest(sockfd);

	/* triggr programs based on Runscript */

	struct rs_data *ptr = NULL;
	while ((ptr = get_RunScript()) != NULL) {	
		const char *cmd = get_RunScript_command(ptr);
		printf("RS:[%s]\n", cmd);

		//triggerRunScript(cmd);
		system(cmd);
		free(ptr);
	}

	/* turn on powermemo*/
	pid_t pid = triggerPowerMemo();

	/* wait for End section */
	struct pm_prefix pm_pfx;
	int n = read(sockfd, &pm_pfx, sizeof(pm_pfx));
	if (n < 0 || n == 0) {
		exit(EXIT_FAILURE);
	}

	if (pm_pfx.type == END_SECTION) {
		/* turn off powermemo */
		kill(pid, SIGUSR1);
	} else {
		fprintf(stderr, "Error: not an End Section singal!\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "memo should be dead already!\n");


	/* notify the server that we are done*/
	write(sockfd, &pm_pfx, sizeof(pm_pfx));


	return 0;
}

static void sig_chld_reaper(int signo)
{
	int status;
	while (wait3(&status, WNOHANG, (struct rusage*)0) > 0);
}


static void triggerRunScript(const char *cmd)
{
	pid_t pid = fork();
	if (pid < 0) {
	} else if (pid == 0) {
		system(cmd);
		exit(EXIT_SUCCESS);
	} else {
		/* parent*/
		printf("child sh pid: %u\n", pid);
	}

}


static int triggerPowerMemo()
{

	signal(SIGCHLD, sig_chld_reaper);
	pid_t pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	} else if (pid == 0) {

		close(sockfd);

		const char pm_name[] = "/data/powermemo/memo";
		/* please change this to fit your config !!!*/

		fprintf(stderr, "memo path: [%s]\n", pm_name);

		char *cmd[] = {"memo", "5", "10000", (char*)0};
		int ret = execv(pm_name, cmd);

		fprintf(stderr,"Exec: %d\n", ret);

		exit(ret);

	} else {

		return pid;
	}

}


