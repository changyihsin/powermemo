/*
 *      RS232_trigger.c
 *      
 *      Copyright 2010 brass-is <brass-is@brass-is-laptop>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>  
#include <sys/ioctl.h>
#include <linux/serial.h>

#include "RS232_trigger.h"

static int fd;
static struct termios oldterminfo;


void erroropenserial(char *devicename)
{
     fprintf(stderr, "Could not open device file %s.\n", devicename);
     exit(EXIT_FAILURE);
}

int closeserial(void)
{
     tcsetattr(fd, TCSANOW, &oldterminfo);
     if (close(fd) == -1) {
	  perror("closeserial() error");
	  return 0;
     }
     return 1;
}

void openserial(char *devicename)
{
     struct termios attr;

     if ((fd = open(devicename, O_RDWR)) == -1) { 
	  perror("openserial(): open()");
	  erroropenserial(devicename);
     }
     if (tcgetattr(fd, &oldterminfo) == -1) {
	  perror("openserial(): tcgetattr()");
	  closeserial();
	  erroropenserial(devicename);
     }
     attr = oldterminfo;
     attr.c_cflag |= CRTSCTS | CLOCAL;
     attr.c_oflag = 0;
     if (tcflush(fd, TCIOFLUSH) == -1) {
	  perror("openserial(): tcflush()");
	  closeserial();
	  erroropenserial(devicename);
     }
     if (tcsetattr(fd, TCSANOW, &attr) == -1) {
	  perror("initserial(): tcsetattr()");
	  closeserial();
	  erroropenserial(devicename);
     }
}

int setRTS(unsigned short level)
{
     int status;

     if (ioctl(fd, TIOCMGET, &status) == -1) {
	  perror("setRTS() error");
	  return 0;
     }
     if (level) status |= TIOCM_RTS;
     else status &= ~TIOCM_RTS;
     if (ioctl(fd, TIOCMSET, &status) == -1) {
	  perror("setRTS() error");
	  return 0;
     }
     return 1;
}


int setDTR(unsigned short level)
{
     int status;

     if (ioctl(fd, TIOCMGET, &status) == -1) {
	  //perror("setDTR() error\n");
	  return 0;
     }
     if (level) status |= TIOCM_DTR;
     else status &= ~TIOCM_DTR;
     if (ioctl(fd, TIOCMSET, &status) == -1) {
	  //perror("setDTR() error\n");
	  return 0;
     }
     return 1;
}
