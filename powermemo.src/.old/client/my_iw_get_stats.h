/*
 *      my_iw_get_stats.h
 *      
 *      Copyright 2010 BRASS LAB - All rights reserved
 * 			National Chiao Tung University, Hsinchu,TAIWAN R.O.C.
 * 			Developed by Ilter Suat <iltersuat@gmail.com>
 * 			
 * 			This is basically a copy&paste block of code from Wireless Extensions.
 *      Please see iw_get_stats() in iwlib.c
 *			
 *			Header file for the my_iw_get_stats.c
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
#include <string.h> 
#include <stdlib.h> 
#include <ctype.h>
#include <asm/types.h>

/*
 *      Quality of the link
 */
struct  iw_quality
{
        __u8            qual;           /* link quality (%retries, SNR,
                                           %missed beacons or better...) */
        __u8            level;          /* signal level (dBm) */
        __u8            noise;          /* noise level (dBm) */
        __u8            updated;        /* Flags to know if updated */
};


 /* Wireless statistics (used for /proc/net/wireless)
 */
struct  iw_statistics
{
        __u16           status;         /* Status
                                         * - device dependent for now */

        struct iw_quality       qual;           /* Quality of the link
                                                 * (instant/mean/max) */
        //struct iw_discarded     discard;        /* Packet discarded counts */
        //struct iw_missed        miss;           /* Packet missed counts */
};

/* If succeeds, it modifies "stats" and returns 0,
 * if fails,it does not modify "stats" returns -1.
 */
int my_iw_get_stats(struct iw_statistics *stats, char *ifname);
