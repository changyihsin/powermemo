

#include <sys/ioctl.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>

/* Use 'x' as magic number */
#define POWERMEMO_IOCTL_MAGIC  'x'

#define POWERMEMO_IOCTL_BEGINTEST	 _IOW(POWERMEMO_IOCTL_MAGIC,  1, int32_t)
#define POWERMEMO_IOCTL_ENDTEST		 _IOW(POWERMEMO_IOCTL_MAGIC,  2, int32_t)
#define POWERMEMO_IOCTL_MARKERENTRY    _IOW(POWERMEMO_IOCTL_MAGIC,  3, int32_t)
#define POWERMEMO_IOCTL_MARKEREXIT     _IOW(POWERMEMO_IOCTL_MAGIC,  4, int32_t)

#include "powermemo_data.h"
#include "decode.h"

#define	BUFFER_LEN	1024*1024*4

#define err_exit(format,arg...)			exit(fprintf(stderr,format,##arg))

static int devfd = -1;

/* for SIGUSR1 signal */
static void sig_handler(int signo)
{
	if (ioctl(devfd, POWERMEMO_IOCTL_ENDTEST, -1) != 0) {
		err_exit("ioctl error on /dev/powermemo...\n");
	}

	exit(EXIT_SUCCESS);
}


int main(int argc, char* argv[])
{

	unsigned char buffer[sizeof(unsigned char) * (BUFFER_LEN + 16)];
	char ch;

	FILE *fPU = NULL, *fMK = NULL, *fXMIT = NULL, *fRCV = NULL;

	int pun = 0, mkn = 0, xmitn = 0, rcvn = 0;

	//int read_flag = 0;
	int end_flag = 0;

	if (argc < 3) {
		printf("too few args.\n");
		exit(EXIT_FAILURE);
	}

	unsigned int count = 0;
	unsigned int bound = atoi(argv[1]);
	unsigned int delay_level = atoi(argv[2]);
	printf("bound: %d time(s)\n", bound);

	/* for shut down manually*/
	signal(SIGUSR1, sig_handler);

	devfd = open("/dev/powermemo", O_RDONLY);
	if (devfd == -1) {
		perror("/dev/powermemo open");
		exit(EXIT_FAILURE);
	}



	printf("begin\n");

	read(devfd, (unsigned char*)buffer, sizeof(unsigned char) * BUFFER_LEN);
	sleep(1);

	fPU = fopen("pu.dat", "w+");
	if (fPU == NULL) {
		perror("fPU open");
		exit(EXIT_FAILURE);
	}

	fMK = fopen("mk.dat", "w+");
	if (fMK == NULL) {
		perror("fMK open");
		exit(EXIT_FAILURE);
	}

	fXMIT = fopen("xmit.dat", "w+");
	if (fXMIT == NULL) {
		perror("fXMIT open");
		exit(EXIT_FAILURE);
	}

	fRCV = fopen("rcv.dat", "w+");
	if (fRCV == NULL) {
		perror("fRCV open");
		exit(EXIT_FAILURE);
	}


	if (ioctl(devfd, POWERMEMO_IOCTL_BEGINTEST, -1) != 0)
	{
		close(devfd);
		err_exit("ioctl error on /dev/powermemo...\n");	
	}


	while (count < bound) {
		printf("count: %d\n", count);
		++count;

		usleep(1024 * delay_level);

		int n = read(devfd, (unsigned char*)buffer, sizeof(unsigned char)*BUFFER_LEN);
		fprintf(stderr, "Read size:[%d]\n", n);
		pun = decode_pu(buffer + 4, fPU);
		mkn = decode_mk(buffer + 4 + pun, fMK);
		xmitn = decode_xmit(buffer + 4 + pun + mkn, fXMIT);
		rcvn = decode_rcv(buffer + 4 + pun + mkn + xmitn, fRCV);
		fprintf(stdout,"Written to disk,%d,%d,%d,%d\n", pun, mkn, xmitn, rcvn);
	} 


	printf("end\n");

	if (ioctl(devfd, POWERMEMO_IOCTL_ENDTEST, -1) != 0) {
		close(devfd);
		err_exit("ioctl error on /dev/powermemo...\n");
	}

	sleep(2);

	//while (1)
	{
		int n = read(devfd, (unsigned char*)buffer, sizeof(unsigned char)*BUFFER_LEN);

	//	if (n <= 4)
	//	{
	//		fprintf(stderr, "Read out of data size: %d\n", n);
	//		break;
	//	}
		fprintf(stderr, "Read size: %d\n", n);

		pun = decode_pu(buffer + 4, fPU);
		mkn = decode_mk(buffer + 4 + pun, fMK); 
		xmitn = decode_xmit(buffer + 4 + pun + mkn, fXMIT);
		rcvn = decode_rcv(buffer + 4 + pun + mkn + xmitn, fRCV);

	}
	printf("End test\n");
	exit(EXIT_SUCCESS);
}







