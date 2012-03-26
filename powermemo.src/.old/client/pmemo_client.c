/*
 *      pmemo_client.c
 *      
 *      Copyright 2010 BRASS LAB - All rights reserved
 * 			National Chiao Tung University, Hsinchu,TAIWAN R.O.C.
 * 			Developed by Ilter Suat <iltersuat@gmail.com>
 * 			    
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *      
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *      
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 */

#define _GNU_SOURCE /* for fcloseall() and some other GNU funcs */

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <string.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <sched.h>
#include <stdint.h>

#include "my_iw_get_stats.h"

/* Use 'x' as magic number */
#define POWERMEMO_IOCTL_MAGIC  'x'

#define POWERMEMO_IOCTL_BEGINTEST    	 _IOW(POWERMEMO_IOCTL_MAGIC,  1, int32_t)
#define POWERMEMO_IOCTL_ENDTEST     	 _IOW(POWERMEMO_IOCTL_MAGIC,  2, int32_t)
#define POWERMEMO_IOCTL_MARKERENTRY    _IOW(POWERMEMO_IOCTL_MAGIC,  3, int32_t)
#define POWERMEMO_IOCTL_MARKEREXIT     _IOW(POWERMEMO_IOCTL_MAGIC,  4, int32_t)

/* If you want to record process names(comm) in the powermemo kernel module, 
 * you must define RECORD_COMM in both powermemo.c and pmemo_client.c. 
 * If you don't want, then you must undefine it in both files!
 * Use "#define RECORD_COMM" 
 */
#define RECORD_COMM

#include "RS232_trigger.h"
#include "powermemo_data.h"

#ifndef INADDR_NONE 
#define INADDR_NONE 			0xffffffff 
#endif /* INADDR_NONE */ 
 
//extern int32_t errno; 
#define err_exit(format,arg...) 		exit(fprintf(stderr,format,##arg)) 

#define 	BUFFER_LEN 				1024*1024*4 //4MB
#define 	COMMAND_LEN 			16

#define 	TMP_SIZE					16

#define DEBUG

int32_t decode_pu (unsigned char *pbuf, FILE *fd)
{
	struct processor_u *pu;
	int32_t i;
	int32_t nr_p_u = *(int32_t *)pbuf;
	
/*	if(fd == NULL) {
		perror(NULL);
		fprintf(stderr,"\npu.dat is not opened!\n");
		exit(1);
	}
*/
  
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
	
/*	if(fd == NULL) {
		perror(NULL);
		fprintf(stderr,"\npu.dat is not opened!\n");
		exit(1);
	}
*/
  
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
	
/*	if(fd == NULL) {
		perror(NULL);
		fprintf(stderr,"\nxmit.dat is not opened!\n");
		exit(1);
	}
*/
  
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
	
/*	if(fd == NULL) {
		perror(NULL);
		fprintf(stderr,"\nrcv.dat is not opened!\n");
		exit(1);
	}
*/
  
	for(i=0; i<nr_rcv_u; i++){
		rcv = (struct rcv_u *)(pbuf + 8 + i * sizeof(struct rcv_u));
		fprintf(fd,"%d,%d,%ld,%ld\n",rcv->pid, rcv->rx_bitrate, rcv->packet_size, rcv->t_arrival);
	}
	
	sync(); //sync() doesn't block
  
	return 8 + nr_rcv_u * sizeof(struct rcv_u);
}


/*------------------------------------------------------------------------ 
 * connectsock - allocate & connect a socket using TCP or UDP 
 *------------------------------------------------------------------------ 
 */ 
int32_t connectsock(const char *host, const char *service, const char *transport) 
{ 
    struct hostent *phe; /* pointer to host information entry */ 
    struct servent *pse; /* pointer to service information entry */ 
    struct sockaddr_in sin; /* an Internet endpoint address */
    int32_t s, type; /* socket descriptor and socket type */ 
 
 
    memset(&sin, 0, sizeof(sin)); 
    sin.sin_family = AF_INET; 
 
    /* Map service name to port number */ 
    if ((pse = getservbyname(service, transport))) 
    {
			sin.sin_port = pse->s_port; 
		}
    else if ((sin.sin_port=htons((unsigned short)atoi(service))) == 0) 
    {
			    err_exit("can't get \"%s\" service entry\n", service); 
		}
 
    /* Map host name to IP address, allowing for dotted decimal */ 
    if ((phe = gethostbyname(host))) 
        memcpy(&sin.sin_addr, phe->h_addr, phe->h_length); 
    else if ( (sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE ) 
        err_exit("can't get \"%s\" host entry\n", host); 
 
 
    /* Use protocol to choose a socket type */ 
    if (strcmp(transport, "udp") == 0) 
        type = SOCK_DGRAM; 
    else  type = SOCK_STREAM; 
   
    /* Allocate a socket */ 
    s = socket(PF_INET, type, 0); 
    if (s < 0) 
        err_exit("can't create socket: %s\n", strerror(errno)); 
 
    /* Connect the socket */ 
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
        err_exit("can't connect to %s:%s: %s\n", host, service,strerror(errno)); 
    return s; 
} 

int32_t main(int32_t argc, char *argv[]) 
{ 
	int32_t socket; /* socket descriptor */ 
	int32_t devfd; /* device file descriptor */
	FILE *fPU = NULL, *fMK = NULL, *fXMIT = NULL, *fRCV = NULL;
	
	int32_t i=0,n=0;
	int32_t read_cnt=0,read_delay = 100, read_flag = 0;
	int32_t pun=0,mkn=0,xmitn=0,rcvn=0;

	char sCommand[COMMAND_LEN]; memset(sCommand,'\0',COMMAND_LEN);
	unsigned char pBuffer[BUFFER_LEN+8];

  int32_t end_flag = 0;
	
	char ifname[] = "wlan0"; /* interface name of our wlan card*/
	struct iw_statistics stats;
	int16_t signal_level = 0;
	char ssignal_level[16]; memset(ssignal_level,'\0',16);
	char tmp[TMP_SIZE]; memset(tmp,'\0',TMP_SIZE);
	 	
 	if(argc < 3){ 		
     	fprintf(stdout,"usage: %s host_address host_port serial_device read_count\n",argv[0]); 
			fprintf(stdout,"Ex: pmemo_client 192.168.0.10 8001 /dev/ttyS0 10\n");
			fprintf(stdout,"\nBefore you execute this control daemon, you must:\n");
			fprintf(stdout,"  1. have wlan card driver module inserted and wireless connection established.\n");
			fprintf(stdout,"  2. have powermemo.ko module inserted.\n");
			fprintf(stdout,"  3. have physical connections established as described in the manual.\n");
     	exit(1); 
 	}
	
	//Here we are becoming a real-time process-->not a good idea anymore!
  //set_schedule(); 
	
	/* char *serial_dev = (argc>=4) ? argv[3]:"/dev/ttyS0"; */
	char *serial_dev = argv[3];
	
	read_delay = atoi(argv[4]);
	if(read_delay < 0){
		fprintf(stdout,"read_delay can't be smaller than 0,using 100 as default\n");
		read_delay = 100;
	}
	
  /* connect the socket */
  socket=connectsock(argv[1],argv[2], "tcp"); 

	devfd = open("/dev/powermemo", O_RDONLY); 
	if(devfd == -1) {
		perror("/dev/powermemo open");
		exit(EXIT_FAILURE);
	}
	
	openserial(serial_dev);

	while(end_flag!=1){
    		
		n=0;
		//do{
			//n = read(socket,(unsigned char*)sCommand,sizeof(char)*COMMAND_SIZE);
			//This is non-blocking I/O
			n = recv(socket, (char*)sCommand, sizeof(char)*COMMAND_LEN, MSG_DONTWAIT);
		//}while(n<COMMAND_LEN);
#ifdef DEBUG				
		if(sCommand[0] != 0){
			fprintf(stdout,"\nCommand '%s' received\n",sCommand);
		}
#endif
		n=0;
    
		switch(sCommand[0]){
		case 'C': /* CALIBRATION */
			fprintf(stdout,"Calibration begins...\n");

			/* This is for the first time when we set attenuation to 0.
			 * Later this loop will receive the values from host
			 */ 
			sCommand[0] = 'd'; sCommand[1] = 'B'; sCommand[2] ='0'; sCommand[3] = '\0';
			/* Attenuator starts from 0.0dB, steps up 2dB and reaches 62dB in 32steps 
			 */
			do 
			{	
				/* Parse /proc/net/wireless for signal level value */
				if(-1 == my_iw_get_stats(&stats,ifname))
				{
					/* Complain and then use the previous signal level for this step */
					fprintf(stderr,"Can't parse the /proc/net/wireless\n");
					signal_level = stats.qual.level-0xFF;
				}
				else
				{ 
					signal_level = stats.qual.level-0xFF;
					fprintf(stdout,"ifname=%s,level=%d - attenuation=%s\n",ifname,signal_level,sCommand);
					
					sprintf(ssignal_level,"SIG%d",signal_level);

					fprintf(stdout,"ssignal_level = %s\n",ssignal_level);

					if(-1 == write(socket,ssignal_level,strlen(ssignal_level))) 
					{
						fprintf(stderr,"Can't send signal level to host...\n");
						//fcloseall();
						exit(EXIT_FAILURE);
					}
					sync();
					
					/* This time recv() blocks... */
					n = recv(socket, (char*)sCommand, sizeof(char)*COMMAND_LEN, 0);
					if(sCommand[0] == 'C' && sCommand[2] == 'N') /* CANCEL */
					{
						fprintf(stdout,"Calibration was cancelled by host...\n");
						break;
					}
					//ENDCALIB
					else if(sCommand[0] == 'E' && sCommand[3] == 'C')
					{
						fprintf(stdout,"Calibration has ended...\n");
						fprintf(stdout,"Probably WLAN connection has been lost, reconnecting...\n");
						system("sh connect2wlan.sh");
						break;
					}
				}
				
			}while(1); 
			read_flag = 0;
			
			
			//clear it
			sCommand[0] = '\0'; sCommand[1] = '\0'; 			
			break;
		
		case 'B': /* BEGINTEST */
			/* When we load a mobility script, target may lose the existing WLAN connection.
			 * It is more convenient to reconnect it automatically.
			 */ 
			system("sh connect2wlan.sh &");
			sleep(6);
			
			fprintf(stdout,"benchmarks are running now...\n");


			/* flush any remaining data from a previous profiling */
#ifdef DEBUG
			fprintf(stdout,"Flushing the module buffer first...\n");
#endif
			read(devfd, (unsigned char*)pBuffer, sizeof(unsigned char)*BUFFER_LEN);			

			sleep(1);
			
			/* OPEN THE .dat FILES HERE */
#warning EVERY TIME A TEST BEGINS,  THESE DATA FILES ARE RE-OPENED AND TRUNCATED TO ZERO
			fPU = fopen("/mnt/sda1/pu.dat","w+"); //file will be truncated to zero every time
			if(fPU == NULL) {
				//closeserial();close(devfd);
				//fcloseall();
				perror("fPU open");
				exit(EXIT_FAILURE);
			}
			fMK = fopen("/mnt/sda1/mk.dat","w+"); //file will be truncated to zero every time
			if(fMK == NULL) {
				//closeserial();close(devfd);fclose(fPU);
				//fcloseall();
				perror("fMK open");
				exit(EXIT_FAILURE);
			}
			fXMIT = fopen("/mnt/sda1/xmit.dat","w+"); //file will be truncated to zero every time
			if(fXMIT == NULL) {
				//closeserial();close(devfd);fclose(fPU),fclose(fMK);
				//fcloseall();
				perror("fXMIT open");
				exit(EXIT_FAILURE);
			}
			fRCV = fopen("/mnt/sda1/rcv.dat","w+"); //file will be truncated to zero every time
			if(fRCV == NULL) {
				//closeserial();close(devfd);fclose(fPU),fclose(fMK);fclose(fXMIT);
				//fcloseall();
				perror("fRCV open");
				exit(EXIT_FAILURE);
			}
			
			//Trigger the DTR pin of ttyS0
			setDTR(0);setDTR(0);setDTR(0);setDTR(0);
			for(i=0;i<10;i++)
			{
				if(setDTR(1) == 0){ //voltage level will rise up fro -6V to +6V
					closeserial();close(devfd);
					err_exit("setDTR() error\n");
				}
			}
			closeserial(); //we don't need it anymore

			//set the read_flag to read from device file at each iteration
			read_flag = 1;

			//send command to the module to start profiling
			if(ioctl(devfd,POWERMEMO_IOCTL_BEGINTEST,-1) != 0)
			{
				close(devfd);
				err_exit("ioctl error on /dev/powermemo...\n");	
			}

			/* All CPU benchmarks can be executed here in a shell script */
			/////system("sh -c" + network_bench)
			system("sh runtest.sh &");
			
			fprintf(stdout,"benchmarks are running now...\n");

			break;
		
		case 'E':
			//send command to the module to stop logging in kernel
			if(ioctl(devfd,POWERMEMO_IOCTL_ENDTEST,-1) != 0)
			{
				//closeserial();fclose(fPU);fclose(fMK);fclose(fRCV);fclose(fRCV);close(devfd);
				//fcloseall();
				//sync(); //flush the kernel buffers to disk
				perror(NULL);
				err_exit("ioctl error on /dev/powermemo...\n");		
			}
			sleep(1); 
			//now read the last items from the device and write to the .dat file
			read(devfd, (unsigned char*)pBuffer, sizeof(unsigned char)*BUFFER_LEN);
			pun = decode_pu(pBuffer+4, fPU); //processor usage items 
			mkn = decode_mk(pBuffer+4+pun, fMK); //marker function items
			xmitn = decode_xmit(pBuffer+4+pun+mkn, fXMIT); //xmit items
			rcvn = decode_rcv(pBuffer+4+pun+mkn+xmitn, fRCV); //rcv items
#ifdef DEBUG
			fprintf(stdout,"\nLast read&write of device file's ended\n");
#endif
			
			strcpy(sCommand,"EOK");
			if(-1 == write(socket,sCommand,strlen(sCommand))) 
			{
				//write() failed, try once more!
#ifdef DEBUG				
				fprintf(stderr,"Can't send '%s' to host...Reason:%s\n",sCommand,strerror(errno));
				fprintf(stderr,"Trying once more...");
#endif
				if(-1 == write(socket,sCommand,strlen(sCommand))) 
				{
					//closeserial();fclose(fPU);fclose(fMK); fclose(fXMIT);fclose(fRCV);close(devfd);
					//fcloseall();
					//sync(); //flush the kernel buffers to disk
					perror(NULL);
					err_exit("Failed again, exiting...\n");
				}
			}
			fsync(socket); /* fsync() blocks! */
#ifdef DEBUG				
			fprintf(stdout,"%s sent\n",sCommand);
#endif

			fprintf(stdout, "closing the files\n");
			/* Everything is OK till here... */
			fclose(fPU);
			fclose(fMK);
			fclose(fXMIT);
			fclose(fRCV);
			sync();
			
			system("sh stoptest.sh");
			read_flag = 0; /* reset it to stop reading from device file */
			end_flag = 1; /* means exit! */
			
	
			n = 0;
			do{
				if(!system("sh send2host.sh")) /* I used ftpput in the script, any other method can be used */
				{ 
					fprintf(stdout,"Sending .dat files, try count %d: OK!\n",n);
					break;
				}
				else
				{ /* system() returned error,transfer failed */
					fprintf(stdout,"Sending .dat files, try count %d: FAILED!\n",n);
				}
				n++;
			}while(n<3);
				
			
			break;
		
		}/* switch */
		
		/* clear it */
		sCommand[0] = '\0'; sCommand[1] = '\0'; 			 

		/* This sleep is very important. If we don't sleep, then we always loop, this makes schedule()
		 * in the kernel very busy,then it makes us very busy here as well...pu.dat can grow huge in a few mins...
		 */
		usleep(read_delay * 1024); /*1024 is for optimization.It sleeps "read_delay" many ms */ 
		
		/* read_delay is given by user through CLI */
		/* if((++read_cnt > read_delay) && read_flag){ */
		if(read_flag){
			/* read_cnt = 0; */
			read(devfd, (unsigned char*)pBuffer, sizeof(unsigned char)*BUFFER_LEN);
#ifdef DEBUG_FULL
			fprintf(stdout,"Read from device\n");
#endif
			pun = decode_pu(pBuffer+4, fPU); //processor usage items 
			mkn = decode_mk(pBuffer+4+pun, fMK); //marker function items
			xmitn = decode_xmit(pBuffer+4+pun+mkn, fXMIT); //xmit items
			rcvn = decode_rcv(pBuffer+4+pun+mkn+xmitn, fRCV); //rcv items
#ifdef DEBUG_FULL
			fprintf(stdout,"Written to disk,%d,%d,%d,%d\n",pun,mkn,xmitn,rcvn);
#endif
		}
		
	}/* while */

	fprintf(stdout,"pmemo_client exiting...\n");
	//fcloseall();
	
  return 0; 
}
