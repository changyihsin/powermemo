/*
 *      powermemo.c
 *      
 *      Copyright 2010 BRASS LAB - All rights reserved
 * 			National Chiao Tung University, Hsinchu,TAIWAN R.O.C.
 * 			Developed by Ilter Suat <iltersuat@gmail.com>
 * 
 * 			
 * 			A small portion of this code in this file is from EPEN research
 * 			< EPEN -- an energy efficient programming environment >
 *			< Copyright (C) 2008 National Science Fundation All rights reserved >
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

//#if defined(CONFIG_MODVERSIONS) && ! defined(MODVERSIONS)
//#include <linux/modversions.h>
//#define MODVERSIONS
//#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h> 
  
//#include <linux/config.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/nmi.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/completion.h>
#include <linux/prefetch.h>
#include <linux/compiler.h>
#include <linux/sched.h>    
#include <linux/tty.h>  
#include <linux/slab.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilter Suat");

#include <asm/uaccess.h>
#include <asm/mmu_context.h>

#include <linux/powermemo.h> 

/*
#define SAMPLERATE				100000 //don't use this directly
#define SCALEDRATE				SAMPLERATE/10 //scale down, host should scale it up
#define SCALEDINTERVAL		((1/SCALEDRATE)*1000000) = 10 (We can't use floating point in kernel)
#define SCALEDINTERVAL			10
*/

/* #define DEBUG_FULL */
#define DEBUG_MIN

int init_module(void);
void cleanup_module(void);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static long device_ioctl(struct file *, unsigned int cmd, unsigned long arg);
	
#define SUCCESS 0
#define DEVICE_NAME "chardev" /* Dev name as it appears in /proc/devices   */
#define BUF_LEN  256            /* Max length of the message from the device */
	
	
/* Global variables are declared as static, so are global within the file. */
	
static int Major;            /* Major number assigned to our device driver */
static int Device_Open = 0;  /* Is device open?  Used to prevent multiple  */
                             /* access to the device                       */
static char msg[BUF_LEN];    /* The msg the device will give when asked    */
static char *msg_Ptr;
	
static struct file_operations fops = {
  .read = device_read, 
  .write = device_write,
	.unlocked_ioctl = device_ioctl,
  .open = device_open,
  .release = device_release
};


static struct timeval sync_tv;  //the time point synchronized with the PC+DAQ
static int sync_flag = 0; //this flag will be set in device_write() for once


/* If you want to record process names(comm), you must decrease the buffer size.
 * Smaller buffer size sometimes causes buffer-overflow,especially when the schedule() is too busy.
 * Use "#define RECORD_COMM"
 */
#define RECORD_COMM

#ifdef RECORD_COMM
#define PU_BUF_LEN		6900
#else
#define PU_BUF_LEN		10000
#endif

#define MK_BUF_LEN			256 /* only 8bits are used for fid in ioctl(), so we can have max 256 marker functions */
#define XMIT_BUF_LEN		4100
#define RCV_BUF_LEN			4100


/* In the original EPEN code, the first 4 bytes are used to store the 
 * nr_processor_u / nr_disk_u / nr_nictx_u / nr_nicrx_u, and the second 4 bytes are 
 * used to store the merged_tx_count / merged_rx_count / merged_d_count /  merged_p_count.
 * 
 * We don't use nr_disk_u and all the merged_XXX items in powermemo, but we keep the original
 * structure as it is.
 * ===> this is why we always add 8bytes to processor_buf / markerfunc_buf / xmit_buf / rcv_buf
 */

/* We use double buffering technique here: When user-daemon reads from kernel module, while one of 
 * the buffer is being flushed out to user-space, and the other one is continued to be filled 
 * by kernel module.
 */
static char *processor_buf; 
static char *processor_buf1;  /* define 2 bufs for double buffering */
static char *processor_buf2;   

static char *markerfunc_buf;
static char *markerfunc_buf1;
static char *markerfunc_buf2;

static char *xmit_buf;
static char *xmit_buf1;
static char *xmit_buf2;

static char *rcv_buf;
static char *rcv_buf1;
static char *rcv_buf2;


extern powermemo_functions powermemofuncs;

/*
 *  These functions may be called from interrupts, so they can NOT sleep.
 *  AN IMPORTANT ASSUMPTION: We assume target CPU is unicore. We did not use any data syncronization. Be careful.
 */
unsigned long gettime(void);
void switch_buffer(void);
int process_slice_entry(int pid, char *comm);
int process_slice_exit(int pid);
int markerfunc_entry(int pid, int fid);
int markerfunc_exit(int pid, int fid);
int xmit_entry(int pid, int bitrate, unsigned long packet_size); /* Since we use a power model for network profiling, */
int rcv_entry(int pid, int bitrate, unsigned long packet_size);	 /* we don't need _exit() for xmit and rcv */


int transfer_to_user(char *buffer);
void powermemo_init(void);
void powermemo_exit(void);


/* Kernel preempting has been disabled in our kernel image */
static int flag_process_slice_started = 0;
static int flag_markerfunc_started = 0;
static struct processor_u *pu = 0;
static struct markerfunc_u *mk = 0;
static struct xmit_u *xmit = 0;
static struct rcv_u *rcv = 0;

static unsigned long xmit_p_size = 0;
static unsigned long rcv_p_size = 0;


#include "powermemo_data.h"

unsigned long gettime(void)
{

    struct timeval tv;
    unsigned long diff;
 
    do_gettimeofday(&tv);
	
  /* calculate the time elapsed in granularity of 20 microseconds
	 * since the module is loaded. 
	 * sync_tv is filled when the client triggers this device with an IOCTL call
	 */
	diff =  (tv.tv_sec - sync_tv.tv_sec)* 50000 + 
            (tv.tv_usec - sync_tv.tv_usec) / 20; 
			/* remember that you can't use floating point numbers in kernel. If you really need,
			 * use shift operators
			 */
			
   /* The diff will overflow in about 24hours - long is 4 byte, 
    2^32/(3600*1000*50) = 23.86 hr */
#ifdef DEBUG_FULL
	printk("\ndiff = %ld\n",diff);
#endif
    return diff;
}

/*this is where double buffer working this is also called when we initalize the buffers */
void switch_buffer(void)
{

    struct processor_u *pu2;
		struct markerfunc_u *mk2;


    local_irq_disable();   /* in case the read_intr/write_intr preempt this function */
			  
    
    if(processor_buf == processor_buf1)
				processor_buf = processor_buf2; 
    else
				processor_buf = processor_buf1; 
		/****************************************/
    if(markerfunc_buf == markerfunc_buf1)
				markerfunc_buf = markerfunc_buf2; 
    else
				markerfunc_buf = markerfunc_buf1; 
		/****************************************/
		if(xmit_buf == xmit_buf1)
				xmit_buf = xmit_buf2;
		else
				xmit_buf = xmit_buf1;
		/****************************************/
		if(rcv_buf == rcv_buf1)
				rcv_buf = rcv_buf2;
		else
				rcv_buf = rcv_buf1;
		/****************************************/
    
	//clear the nr_processor_u and merged_p_count at each time this function is called
	*(int *)processor_buf = 0; // the first 4 byte(int is 4bytes long) used to put the
			       // nr_processor_u, the second 4byte is used to put the merged_p_count
	*(int *)(processor_buf+4) = 0;
	
	//clear the nr_processor_u and merged_p_count at each time this function is called
	*(int *)markerfunc_buf = 0; // the first 4 byte(int is 4bytes long) used to put the
			       // nr_processor_u, the second 4byte is used to put the merged_p_count
	*(int *)(markerfunc_buf+4) = 0;
	
	//clear the nr_processor_u and merged_p_count at each time this function is called
	*(int *)xmit_buf = 0; // the first 4 byte(int is 4bytes long) used to put the
			       // nr_processor_u, the second 4byte is used to put the merged_p_count
	*(int *)(xmit_buf+4) = 0;

	//clear the nr_processor_u and merged_p_count at each time this function is called
	*(int *)rcv_buf = 0; // the first 4 byte(int is 4bytes long) used to put the
			       // nr_processor_u, the second 4byte is used to put the merged_p_count
	*(int *)(rcv_buf+4) = 0;


		//check if process_slice_entry() was called
    if(flag_process_slice_started && pu){       
        //move the started but not completed process slice info to the new buf
        pu2 = (struct processor_u *)(processor_buf + 8); //remember that the first 8bytes are reserved
        pu2->pid = pu->pid;
#ifdef RECORD_COMM
				memcpy(pu2->comm, pu->comm, 5); /* Actually comm in task_struct holds 16bytes, but because of the memory-limitations, we use 6bytes of it */
				pu2->comm[5] = '\0';
#endif
        pu2->t_entry = pu->t_entry;
        pu = pu2; 
    }/* this check only for the record set that is not completed yet(_finish() not called yet) */

		/* check if process_slice_entry() was called */
    if(flag_markerfunc_started && mk){       
        //move the started but not completed process slice info to the new buf
        mk2 = (struct markerfunc_u *)(markerfunc_buf + 8); //remember that the first 8bytes are reserved
        mk2->pid = mk->pid;
				mk2->fid = mk->fid;
        mk2->t_entry = mk->t_entry;
        mk = mk2; 
    }/* this check only for the record set that is not completed yet(_finish() not called yet) */
    
		/* We don't need to move anything to new buffers for xmit and rcv as they have
		 * only one piece of record in the record set. There is no
		 * possibility for them to be divided into two pieces.
		 */

    local_irq_enable();
   
}


static int flag_processor_buf_full = 0;

int process_slice_entry(int pid,char *comm) 
{
   int nr_processor_u; 
  
	if(!sync_flag){
		printk("sync_tv is not initialized!\n");
		return 0;
	}

   if(flag_process_slice_started == 1){
       printk("pid=%d - a process slice is already marked started\n", pid);
       return 0;
   }

   nr_processor_u = * (int *)processor_buf; 
   /* printk("nr_processor_u=%d\n", nr_processor_u); */

   if(nr_processor_u <PU_BUF_LEN-100 && flag_processor_buf_full){

      flag_processor_buf_full = 0;

   }else if(nr_processor_u >= PU_BUF_LEN-100){ 

      if(flag_processor_buf_full) 
			{ 
				printk("\nflag_processor_buf_full = 1, discarding new items for now\n");
				return 0;
			}
 
      printk("cpu buffer is almost full!\n");

      pu = 0; 
      flag_processor_buf_full = 1;
  

      return 0;

   }
   

	 /* In the original EPEN code, the first 4 bytes are used to store the 
 	  * nr_processor_u / nr_disk_u / nr_nictx_u / nr_nicrx_u, and the second 4 bytes are 
	  * used to store the merged_tx_count / merged_rx_count / merged_d_count /  merged_p_count.
	  * 
	  * We don't use nr_disk_u and all the merged_XXX items in powermemo, but we keep the original
	  * structure as it is.
	  * ===> this is why we always add 8bytes to processor_buf / markerfunc_buf / xmit_buf / rcv_buf
	  */
   pu = (struct processor_u *)(processor_buf + 8 + nr_processor_u * sizeof(struct processor_u));  
   pu->pid = pid;
#ifdef RECORD_COMM
	 memcpy(pu->comm, comm, 5); /* Actually comm in task_struct holds 16bytes, but because of the memory-limitations, we use 6bytes of it */
	 pu->comm[5] = '\0';
#endif
   pu->t_entry = gettime();
   
   /* printk("\npu->t_entry = %d\n",pu->t_entry); */

   flag_process_slice_started = 1;
  

   return 0;
}


int process_slice_exit(int pid) 
{
   unsigned int diff;

   if(!pu) return 0;
   
   	if(!sync_flag){
		printk("sync_tv is not initialized!\n");
		return 0;
	}


   if(flag_process_slice_started == 0){
       printk("start time of this time slice for pid=%d is not recorded\n", pid);
       return 0;
   }

   diff = gettime();
			 
   if(diff > 4290000000 ){ //4294967295 is the max diff can be hold, it takes (4294967296/50000) seconds to overflow
#warning THIS MAY NOT BE UNSIGNED FOR THE C STANDARD USED...
         pu->t_exit = 0;
		 printk("\nThis time slice is longer than the module can handle\n");
#warning I SHOULD HANDLE THIS IN A BETTER WAY!
   }
   else
         pu->t_exit = diff; 
		 
   /* printk("\npu->t_exit = %d\n",pu->t_exit); */
   
   (*(int *)processor_buf)++;    /* the number of processor_u  stored so far */

   flag_process_slice_started = 0;
 
   return 0;
}	

/*==============================Marker functions========================================*/
static int flag_markerfunc_buf_full = 0;
int markerfunc_entry(int pid,int fid) 
{
   int nr_markerfunc_u; 
  
	if(!sync_flag){
		printk("sync_tv is not initialized!\n");
		return 0;
	}

   if(flag_markerfunc_started == 1){
       printk("fid=%d expecting markerfunc_finish()\n", fid);
       return 0;
   }

   nr_markerfunc_u = * (int *)markerfunc_buf; 

   if(nr_markerfunc_u <MK_BUF_LEN-10 && flag_markerfunc_buf_full){

      flag_markerfunc_buf_full = 0;

   }else if(nr_markerfunc_u >= MK_BUF_LEN-10){ 

      if(flag_markerfunc_buf_full) 
			{ 
				printk("\nflag_markerfunc_buf_full = 1, discarding new items for now\n");
				return 0;
			}
 
      printk("marker function buffer is almost full!\n");

      mk = 0; 
      flag_markerfunc_buf_full = 1;

      return 0;

   }
   
	 /* In the original EPEN code, the first 4 bytes are used to store the 
 	  * nr_processor_u / nr_disk_u / nr_nictx_u / nr_nicrx_u, and the second 4 bytes are 
	  * used to store the merged_tx_count / merged_rx_count / merged_d_count /  merged_p_count.
	  * 
	  * We don't use nr_disk_u and all the merged_XXX items in powermemo, but we keep the original
	  * structure as it is.
	  * ===> this is why we always add 8bytes to processor_buf / markerfunc_buf / xmit_buf / rcv_buf
	  */
   mk = (struct markerfunc_u *)(markerfunc_buf + 8 + nr_markerfunc_u * sizeof(struct markerfunc_u));  
   mk->pid = pid;
   mk->fid = fid; /* it will be used when marker functions are used in an application */
   mk->t_entry = gettime();
   
   /* printk("\nmk->t_entry = %d\n",mk->t_entry); */

   flag_markerfunc_started = 1;
  

   return 0;
}


int markerfunc_exit(int pid,int fid) 
{
   unsigned int diff;

   if(!mk) return 0;
   
   	if(!sync_flag){
		printk("sync_tv is not initialized!\n");
		return 0;
	}


   if(flag_markerfunc_started == 0){
       printk("fid=%d expecting markerfunc_finish()\n", fid);
       return 0;
   }

   diff = gettime();
			 
   if(diff > 4290000000 ){ //4294967295 is the max diff can be hold, it takes (4294967296/50000) seconds to overflow
#warning THIS MAY NOT BE UNSIGNED FOR THE C STANDARD USED...
         mk->t_exit = 0;
		 printk("\nThis time slice is longer than the module can handle\n");
#warning I SHOULD HANDLE THIS IN A BETTER WAY!
   }
   else
         mk->t_exit = diff; 
		 

   (*(int *)markerfunc_buf)++;    /* the number of processor_u  stored so far */

   flag_markerfunc_started = 0;
 
   return 0;
}	
/*==============================Marker functions========================================*/

static int flag_xmit_buf_full = 0;
int xmit_entry(int pid, int bitrate, unsigned long packet_size)
{
  int nr_xmit_u; 
  
	if(!sync_flag){
		printk("sync_tv is not initialized!\n");
		return 0;
	}

   nr_xmit_u = * (int *)xmit_buf; 
	 
   if(nr_xmit_u <XMIT_BUF_LEN-100 && flag_xmit_buf_full){

      flag_xmit_buf_full = 0;

   }else if(nr_xmit_u >= XMIT_BUF_LEN-100){ 

      if(flag_xmit_buf_full) 
			{ 
				printk("\nflag_xmit_buf_full = 1, discarding new items for now\n");
				return 0;
			}
 
      printk("xmit buffer is almost full!\n");

      xmit = 0; 
      flag_xmit_buf_full = 1;

      return 0;

   }
   
	 /* In the original EPEN code, the first 4 bytes are used to store the 
 	  * nr_processor_u / nr_disk_u / nr_nictx_u / nr_nicrx_u, and the second 4 bytes are 
	  * used to store the merged_tx_count / merged_rx_count / merged_d_count /  merged_p_count.
	  * 
	  * We don't use nr_disk_u and all the merged_XXX items in powermemo, but we keep the original
	  * structure as it is.
	  * ===> this is why we always add 8bytes to processor_buf / markerfunc_buf / xmit_buf / rcv_buf
	  */
   xmit = (struct xmit_u *)(xmit_buf + 8 + nr_xmit_u * sizeof(struct xmit_u));  
   xmit->pid = pid;
	 xmit->tx_bitrate = (short)bitrate; /* bitrates values are in the order of 100K(540 = 54Mbps),at least for rt73usb... */
   xmit->packet_size = packet_size;
	 xmit->t_departure = gettime();
	 
	 xmit_p_size += packet_size; /* the total number of bytes will be reported to user 
																when powermemo_avail is cleared */
	 
   (*(int *)xmit_buf)++;    /* the number of xmit_u stored so far */

#ifdef DEBUG_FULL
	 printk("xmit_entry:nr_xmit_u=%d,pid=%d,tx_bitrate=%d,len=%d,t_departure=%d\n",(*(int *)xmit_buf), xmit->pid, xmit->tx_bitrate, xmit->packet_size,xmit->t_departure);
#endif
   
   return 0;	
}

static int flag_rcv_buf_full = 0;
int rcv_entry(int pid, int bitrate, unsigned long packet_size)
{
  int nr_rcv_u; 
  
	if(!sync_flag){
		printk("sync_tv is not initialized!\n");
		return 0;
	}

   nr_rcv_u = * (int *)rcv_buf; 

   if(nr_rcv_u <RCV_BUF_LEN-10 && flag_rcv_buf_full){

      flag_rcv_buf_full = 0;

   }else if(nr_rcv_u >= RCV_BUF_LEN-10){ 

      if(flag_rcv_buf_full) 
			{ 
				printk("\nflag_rcv_buf_full = 1, discarding new items for now\n");
				return 0;
			}
 
      printk("rcv buffer is almost full!\n");

      rcv = 0; 
      flag_rcv_buf_full = 1;

      return 0;

   }
   
	 /* In the original EPEN code, the first 4 bytes are used to store the 
 	  * nr_processor_u / nr_disk_u / nr_nictx_u / nr_nicrx_u, and the second 4 bytes are 
	  * used to store the merged_tx_count / merged_rx_count / merged_d_count /  merged_p_count.
	  * 
	  * We don't use nr_disk_u and all the merged_XXX items in powermemo, but we keep the original
	  * structure as it is.
	  * ===> this is why we always add 8bytes to processor_buf / markerfunc_buf / xmit_buf / rcv_buf
	  */
   rcv = (struct rcv_u *)(rcv_buf + 8 + nr_rcv_u * sizeof(struct rcv_u));  
   rcv->pid = pid;
   rcv->rx_bitrate = (short)bitrate; /* bitrates values are in the order of 100K(540 = 54Mbps),at least for rt73usb... */
	 rcv->packet_size = packet_size;
	 rcv->t_arrival = gettime();
	 
	 rcv_p_size += packet_size; /* the total number of bytes will be reported to user 
																when powermemo_avail is cleared */
	 
	 (*(int *)rcv_buf)++;    /* the number of rcv_u stored so far */

#ifdef DEBUG_FULL
	 printk("rcv_entry:nr_rcv_u=%d,pid=%d,rx_bitrate=%d,len=%d,t_arrival=%d\n",(*(int *)rcv_buf),rcv->pid, rcv->rx_bitrate,rcv->packet_size,rx->t_arrival);
#endif
   
   return 0;		
}



/*return total number of bytes copied*/
int transfer_to_user(char *buffer)   
{
  int nr_processor_u;
	int nr_markerfunc_u;
	int nr_xmit_u;
	int nr_rcv_u;
  
	int pbytes;
  int mkbytes;
	int xmitbytes;
	int rcvbytes;
	
	int i=0; 
  char len[4];

  char *pbuf = processor_buf;
	char *mkbuf = markerfunc_buf;
	char *xmitbuf = xmit_buf;
	char *rcvbuf = rcv_buf;
  
	switch_buffer(); 
 
  nr_processor_u = *(int *)pbuf;  
	nr_markerfunc_u = *(int *)mkbuf;  
	nr_xmit_u = *(int *)xmitbuf;
	nr_rcv_u = *(int *)rcvbuf;
  
  pbytes = 8 + nr_processor_u * sizeof(struct processor_u);
	mkbytes = 8 + nr_markerfunc_u * sizeof(struct markerfunc_u);
	xmitbytes = 8 + nr_xmit_u * sizeof(struct xmit_u);
	rcvbytes = 8 + nr_rcv_u * sizeof(struct rcv_u);

  *((int *)len) = 4 + pbytes + mkbytes + xmitbytes + rcvbytes; /* total bytes to send to user-daemon */
 
  for(i=0; i<4; i++){
     put_user(len[i], buffer);
     buffer++; 
  } 
  
  for(i=0; i < pbytes; i++ ){
     put_user(pbuf[i], buffer);
     buffer++;
  }  
	
	for(i=0; i < mkbytes; i++ ){
     put_user(mkbuf[i], buffer);
     buffer++;
  } 

	for(i=0; i < xmitbytes; i++ ){
     put_user(xmitbuf[i], buffer);
     buffer++;
  } 

	for(i=0; i < rcvbytes; i++ ){
     put_user(rcvbuf[i], buffer);
     buffer++;
  } 

  
  return *(int *)len; //total bytes to send 
}



void powermemo_init(void){
	int error = 0;
	
	//remember that first 8 bytes of this buffer is reserved for nr_processor_u and
	//merged_p_count
	processor_buf1 = kmalloc(sizeof(struct processor_u)*PU_BUF_LEN, GFP_KERNEL);
	processor_buf2 = kmalloc(sizeof(struct processor_u)*PU_BUF_LEN, GFP_KERNEL);
	if(!processor_buf1 || !processor_buf2){
		printk("not enough memory!\n");
		error = 1;
	}

	//remember that first 8 bytes of this buffer is reserved for nr_markerfunc_u and
	//merged_p_count
	markerfunc_buf1 = kmalloc(sizeof(struct markerfunc_u)*MK_BUF_LEN, GFP_KERNEL);
	markerfunc_buf2 = kmalloc(sizeof(struct markerfunc_u)*MK_BUF_LEN, GFP_KERNEL);
	if(!markerfunc_buf1 || !markerfunc_buf2){
		printk("not enough memory!\n");
		error = 1;
	}

	//remember that first 8 bytes of this buffer is reserved for nr_markerfunc_u and
	//merged_p_count
	xmit_buf1 = kmalloc(sizeof(struct xmit_u)*XMIT_BUF_LEN, GFP_KERNEL);
	xmit_buf2 = kmalloc(sizeof(struct xmit_u)*XMIT_BUF_LEN, GFP_KERNEL);
	if(!xmit_buf1 || !xmit_buf2){
		printk("not enough memory!\n");
		error = 1;
	}

	//remember that first 8 bytes of this buffer is reserved for nr_markerfunc_u and
	//merged_p_count
	rcv_buf1 = kmalloc(sizeof(struct rcv_u)*RCV_BUF_LEN, GFP_KERNEL);
	rcv_buf2 = kmalloc(sizeof(struct rcv_u)*RCV_BUF_LEN, GFP_KERNEL);
	if(!rcv_buf1 || !rcv_buf2){
		printk("not enough memory!\n");
		error = 1;
	}

    
	powermemofuncs.process_slice_entry = process_slice_entry;
	powermemofuncs.process_slice_exit = process_slice_exit;

	powermemofuncs.markerfunc_entry = markerfunc_entry;
	powermemofuncs.markerfunc_exit = markerfunc_exit;

	powermemofuncs.xmit_entry = xmit_entry;
	
	powermemofuncs.rcv_entry = rcv_entry;

	switch_buffer();
 
}


void powermemo_exit(void){
   powermemo_avail = 0;
  
   /* cannot do the free. kernel may be not finished using the buffers*/
   /*kfree(processor_buf1);
   kfree(processor_buf2);
   kfree(disk_buf1);
   kfree(disk_buf2); 
   */
}


	
int init_module(void)
{
   Major = register_chrdev(0, DEVICE_NAME, &fops);

   if (Major < 0) {
     printk("Registering the character device failed with %d\n", Major);
     return Major;
   }

   printk("<1>I was assigned major number %d.  To talk to\n", Major);
   printk("<1>the driver, create a dev file with\n");
   printk("'mknod /dev/powermemo c %d 0'.\n", Major);
   printk("<1>Try various minor numbers.  Try to cat and echo to\n");
   printk("the device file.\n");
   printk("<1>Remove the device file and module when done.\n");

   powermemo_init();

   return 0;
}
	
	
void cleanup_module(void)
{
   /* Unregister the device */
   powermemo_exit();
   unregister_chrdev(Major, DEVICE_NAME);

}  
	
	
	
/* Called when a process tries to open the device file, like
 * "cat /dev/mycharfile"
 */
static int device_open(struct inode *inode, struct file *file)
{
   /*if (Device_Open) return -EBUSY;*/ /* This device can be used by more than one users */
   Device_Open++;

   msg_Ptr = msg;
   //ilter here: MOD_INC_ and MOD_DEC are deprecated since v2.5. These increase or decrease the usage count of the module
   //use try_module_get(THIS_MODULE) instead
   //MOD_INC_USE_COUNT;
   try_module_get(THIS_MODULE);

   return SUCCESS;
}
	
	
/* Called when a process closes the device file.
 */
static int device_release(struct inode *inode, struct file *file)
{
   Device_Open --;     /* We're now ready for our next caller */

   /* Decrement the usage count, or else once you opened the file, you'll
	    never get get rid of the module. */
   //ilter here: MOD_INC_ and MOD_DEC are deprecated since v2.5. These increase or decrease the usage count of the module
   //use module_put(THIS_MODULE) instead
   //MOD_DEC_USE_COUNT;
   module_put(THIS_MODULE);
	
   return 0;
}
	
	
/* Called when a process, which already opened the dev file, attempts to
*   read from it.
*  This is called from pmemo_client.c to get the timing data from kernel.  
*/

static ssize_t device_read(struct file *filp,
   char *buffer,    /* The buffer to fill with data */
   size_t length,   /* The length of the buffer     */
   loff_t *offset)  /* Our offset in the file       */
{
   /* Actually put the data into the buffer */
   /* The buffer is in the user data segment, not the kernel segment;
    * assignment won't work.  We have to use put_user which copies data from
    * the kernel data segment to the user data segment. */

   
   return transfer_to_user(buffer); //returns the number of bytes read
}
	
	

/*  Called when a process writes to dev file  */
static ssize_t device_write(struct file *filp,
   const char *buff,
   size_t len,
   loff_t *off)
{
 
	return len;
}


/* Use 'x' as magic number */
#define POWERMEMO_IOCTL_MAGIC  'x'

#define POWERMEMO_IOCTL_BEGINTEST    	 _IOW(POWERMEMO_IOCTL_MAGIC,  1, int)
#define POWERMEMO_IOCTL_ENDTEST     	 _IOW(POWERMEMO_IOCTL_MAGIC,  2, int)
#define POWERMEMO_IOCTL_MARKERENTRY    _IOW(POWERMEMO_IOCTL_MAGIC,  3, int)
#define POWERMEMO_IOCTL_MARKEREXIT     _IOW(POWERMEMO_IOCTL_MAGIC,  4, int)

#define POWERMEMO_IOCTL_MAXNR 4 /*we have only 4 commands,if number is grater 
															 * 		than this, error will be returned to user space */

/* 
 * This function is called whenever a process tries to do an ioctl on our
 * device file. We get two extra parameters (additional to the inode and file
 * structures, which all device functions get): the number of the ioctl called
 * and the parameter given to the ioctl function.
 *
 * If the ioctl is write or read/write (meaning output is returned to the
 * calling process), the ioctl call returns the output of this function.
 *
 */
long device_ioctl(struct file *file,	/* ditto */
		 unsigned int cmd,	/* cmd number and argument for ioctl */
		 unsigned long arg)
{
	unsigned int pid = 0 , fid = 0;

/*
	* extract the type and number bitfields, and don't decode
	* wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
*/
  if(_IOC_TYPE(cmd) != POWERMEMO_IOCTL_MAGIC) return -ENOTTY;
  if(_IOC_NR(cmd) > POWERMEMO_IOCTL_MAXNR) return -ENOTTY;

	pid = (arg & 0x00FFFFFF); /* Lowest 24 bits store the pid of the calling process */
	fid = (arg & 0xFF000000) >> 24;  /*Highest 8bits store the marker function id(fid) */


/* 
	* Switch according to the ioctl called 
*/
	switch (cmd) {
		case POWERMEMO_IOCTL_BEGINTEST:
			do_gettimeofday(&sync_tv);
			sync_flag = 1;
			xmit_p_size = 0; //this counter must be cleared before profiling starts
			rcv_p_size = 0; //this counter must be cleared before profiling starts
			powermemo_avail = 1;
#ifdef DEBUG_MIN
			printk("profiling started...\n");
			printk("sync_tv.sec = %lu , sync_tv.usec = %lu",(unsigned long)sync_tv.tv_sec,(unsigned long)sync_tv.tv_usec);
#endif
			break;

		case POWERMEMO_IOCTL_ENDTEST:
			sync_flag = 0;
			powermemo_avail = 0;
#ifdef DEBUG_MIN
			printk("profiling stopped...\n");
			printk("xmit bytes = %lu, rcv bytes = %lu\n",xmit_p_size,rcv_p_size);
#endif
			break;
		
		case POWERMEMO_IOCTL_MARKERENTRY: /*This command gets the PID of the calling user-space process
																			* using ioctl() argument and sends it to the markerfunc_entry()*/
			if(!powermemo_avail) 
			{ printk("\n'POWERMEMO_IOCTL_INIT' must be called first!\n"); return -ENOTTY; }

			markerfunc_entry(pid,fid);
#ifdef DEBUG_MIN
			printk("arg = 0x%lx\n",arg);
			printk("markerfunc_entry(0x%x,0x%x)\n",pid,fid);
#endif
		
		break;
		
		case POWERMEMO_IOCTL_MARKEREXIT: /*This command gets the PID of the calling user-space process
																			* using ioctl() argument and sends it to the markerfunc_entry()*/
			if(!powermemo_avail) 
			{ printk("\n'POWERMEMO_IOCTL_INIT' must be called first!\n"); return -ENOTTY; }

			markerfunc_exit(pid,fid);
#ifdef DEBUG_MIN
			printk("arg = 0x%lx\n",arg);
			printk("markerfunc_exit(0x%x,0x%x)\n",pid,fid);
#endif
		
		break;

	} //switch

	return SUCCESS;
}

