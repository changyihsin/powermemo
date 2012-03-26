

#include <sys/ioctl.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>



/* Use 'x' as magic number */
#define POWERMEMO_IOCTL_MAGIC  'x'

#define POWERMEMO_IOCTL_BEGINTEST	 _IOW(POWERMEMO_IOCTL_MAGIC,  1, int32_t)
#define POWERMEMO_IOCTL_ENDTEST		 _IOW(POWERMEMO_IOCTL_MAGIC,  2, int32_t)
#define POWERMEMO_IOCTL_MARKERENTRY    _IOW(POWERMEMO_IOCTL_MAGIC,  3, int32_t)
#define POWERMEMO_IOCTL_MARKEREXIT     _IOW(POWERMEMO_IOCTL_MAGIC,  4, int32_t)

#define RECORD_COMM
#include "powermemo_data.h"

#define	BUFFER_LEN	1024*1024*4

#define err_exit(format,arg...)			exit(fprintf(stderr,format,##arg))

int32_t decode_pu (unsigned char *pbuf, FILE *fd)
{
	struct processor_u *pu;
	int32_t i;
	int32_t nr_p_u = *(int32_t *)pbuf;

	for(i=0; i<nr_p_u; i++){
		pu = (struct processor_u *)(pbuf + 8 + i * sizeof(struct processor_u));
#ifdef RECORD_COMM
		fprintf(fd,"%d,%s,%ld,%ld\n",pu->pid, pu->comm, pu->t_entry, pu->t_exit);
#else
		fprintf(fd,"%d,#,%ld,%ld\n",pu->pid, pu->t_entry, pu->t_exit);
#endif
	}

	sync(); //sync() doesn't block

	return 8 + nr_p_u * sizeof(struct processor_u);
}


int32_t decode_mk (unsigned char *pbuf, FILE *fd)
{
	struct markerfunc_u *mk;
	int32_t i;
	int32_t nr_markerfunc_u = *(int32_t *)pbuf;

	for(i=0; i<nr_markerfunc_u; i++){
		mk = (struct markerfunc_u *)(pbuf + 8 + i * sizeof(struct markerfunc_u));
		fprintf(fd,"%d,%d,%ld,%ld\n",mk->pid, mk->fid, mk->t_entry, mk->t_exit);
	}

	sync(); //sync() doesn't block

	return 8 + nr_markerfunc_u * sizeof(struct markerfunc_u);
}


int32_t decode_xmit (unsigned char *pbuf, FILE *fd)
{
	struct xmit_u *xmit;
	int32_t i;
	int32_t nr_xmit_u = *(int *)pbuf;

	for(i=0; i<nr_xmit_u; i++){
		xmit = (struct xmit_u *)(pbuf + 8 + i * sizeof(struct xmit_u));
		fprintf(fd,"%d,%d,%ld,%ld\n",xmit->pid, xmit->tx_bitrate,xmit->packet_size,xmit->t_departure);
	}

	sync(); //sync() doesn't block

	return 8 + nr_xmit_u * sizeof(struct xmit_u);
}

int32_t decode_rcv (unsigned char *pbuf, FILE *fd)
{
	struct rcv_u *rcv;
	int32_t i;
	int32_t nr_rcv_u = *(int *)pbuf;

	for(i=0; i<nr_rcv_u; i++){
		rcv = (struct rcv_u *)(pbuf + 8 + i * sizeof(struct rcv_u));
		fprintf(fd,"%d,%d,%ld,%ld\n",rcv->pid, rcv->rx_bitrate, rcv->packet_size, rcv->t_arrival);
	}

	sync(); //sync() doesn't block

	return 8 + nr_rcv_u * sizeof(struct rcv_u);
}



int main(int argc, char* argv[])
{
	
	unsigned char buffer[BUFFER_LEN + 8];
	char ch;

	FILE *fPU = NULL, *fMK = NULL, *fXMIT = NULL, *fRCV = NULL;

	int pun = 0, mkn = 0, xmitn = 0, rcvn = 0;

	int read_flag = 0;
	int end_flag = 0;

	if (argc < 2) {
		printf("too few args.\n");
		exit(EXIT_FAILURE);
	}

	unsigned int count = 0;
	unsigned int bound = atoi(argv[1]);

	int devfd = open("/dev/powermemo", O_RDONLY);
	if (devfd == -1) {
		perror("/dev/powermemo open");
		exit(EXIT_FAILURE);
	}

	ch = 'b';

	while (end_flag != 1) {

		switch (ch) {

			case 'b':

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

				read_flag = 1;

				ch = 'c';

				break;
			case 'e':

				printf("end\n");

				if (ioctl(devfd, POWERMEMO_IOCTL_ENDTEST, -1) != 0) {
					err_exit("ioctl error on /dev/powermemo...\n");
				}

				sleep(1);

				read(devfd, (unsigned char*)buffer, sizeof(unsigned char)*BUFFER_LEN);

				pun = decode_pu(buffer + 4, fPU);
				mkn = decode_mk(buffer + 4 + pun, fMK); 
				xmitn = decode_xmit(buffer + 4 + pun + mkn, fXMIT);
				rcvn = decode_rcv(buffer + 4 + pun + mkn + xmitn, fRCV);

				read_flag = 0;
				end_flag = 1;


				break;
			case 'c':
				++count;
				if (count > bound) {
					ch = 'e';
				}

				break;
			default:
				printf("unknown;");
				break;

		}

		usleep(10240);

		if (read_flag) {
			read(devfd, (unsigned char*)buffer, sizeof(unsigned char)*BUFFER_LEN);

			pun = decode_pu(buffer + 4, fPU);
			mkn = decode_mk(buffer + 4 + pun, fMK);
			xmitn = decode_xmit(buffer + 4 + pun + mkn, fXMIT);
			rcvn = decode_rcv(buffer + 4 + pun + mkn + xmitn, fRCV);
		}

	}


	printf("End test\n");
	return 0;
}







