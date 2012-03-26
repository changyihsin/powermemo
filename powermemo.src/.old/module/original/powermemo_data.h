/*
 *      powermemo_data.h
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

struct processor_u {
   unsigned short pid;
#ifdef RECORD_COMM
	 char comm[6]; /* stores the process name, it is extracted from current/next struct in schedule() */
#endif
   unsigned long t_entry; /* entry time of the time slice */
   unsigned long t_exit; /* exit time of the time slice */
};

struct markerfunc_u {
   unsigned short pid; /*2bytes*/
   unsigned short fid; /*2bytes*/
   unsigned long t_entry; /*4bytes*/
   unsigned long t_exit; /*4bytes*/
};

struct xmit_u {
   unsigned short pid;
	 signed short tx_bitrate;
   unsigned long packet_size;
	 unsigned long t_departure;
};

struct rcv_u {
   unsigned short pid;
	 signed short rx_bitrate;
   unsigned long packet_size;
	 unsigned long t_arrival;
};
