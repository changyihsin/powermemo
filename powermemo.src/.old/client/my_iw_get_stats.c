/*
 *      my_iw_get_stats.c
 *      
 *      Copyright 2010 BRASS LAB - All rights reserved
 * 			National Chiao Tung University, Hsinchu,TAIWAN R.O.C.
 * 			Developed by Ilter Suat <iltersuat@gmail.com>
 * 			
 * 			This is basically a copy&paste block of code from Wireless Extensions.
 *      Please see iw_get_stats() in iwlib.c
 * 			
 * 			This file should be linked with pmemo_client, it needs the function
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

#include "my_iw_get_stats.h"

/*
int main(int argc, char** argv)
{
	char ifname[] = "wlan0";
	struct iw_statistics stats;
	
	if(-1 != my_iw_get_stats(&stats,ifname))
		printf("%s,%u,%u\n",ifname,stats.qual.qual,stats.qual.level);
	
	return 0;
}
*/


/* If succeeds, it modifies "stats" and returns 0,
 * if fails,it does not modify "stats" returns -1.
 */
int my_iw_get_stats(struct iw_statistics *stats, char *ifname)
{
      FILE *    f = fopen("/proc/net/wireless", "r");
      char      buf[256];
      char *    bp;
      int       t;

      if(f==NULL)
        return -1;
      /* Loop on all devices */
      while(fgets(buf,255,f))
        {
          bp=buf;
          while(*bp&&isspace(*bp))
            bp++;
          /* Is it the good device ? */
          if(strncmp(bp,ifname,strlen(ifname))==0 && bp[strlen(ifname)]==':') //if bp begins with smt like "wlan0:", then it is a good device
            {
              /* Skip ethX: */
              bp=strchr(bp,':');
              bp++;
              /* -- status -- */
              bp = strtok(bp, " ");
              sscanf(bp, "%X", &t);
              stats->status = (unsigned short) t;
              /* -- link quality -- */
              bp = strtok(NULL, " ");
              if(strchr(bp,'.') != NULL)
                stats->qual.updated |= 1;
              sscanf(bp, "%d", &t);
              stats->qual.qual = (unsigned char) t;
              /* -- signal level -- */
              bp = strtok(NULL, " ");
              if(strchr(bp,'.') != NULL)
                stats->qual.updated |= 2;
              sscanf(bp, "%d", &t);
              stats->qual.level = (unsigned char) t;
              /* -- noise level -- */
              /*bp = strtok(NULL, " ");
              if(strchr(bp,'.') != NULL)
                stats->qual.updated += 4;
              sscanf(bp, "%d", &t);
              stats->qual.noise = (unsigned char) t;
							*/
              /* -- discarded packets -- */
              /*bp = strtok(NULL, " ");
              sscanf(bp, "%d", &stats->discard.nwid);
              bp = strtok(NULL, " ");
              sscanf(bp, "%d", &stats->discard.code);
              bp = strtok(NULL, " ");
              sscanf(bp, "%d", &stats->discard.misc);
							*/
              fclose(f);
              /* No conversion needed */
              return 0;
            }
        }
      fclose(f);
			return -1;
}
