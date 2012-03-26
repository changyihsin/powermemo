#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>   
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/fs.h>       
#include <linux/errno.h>    
#include <linux/types.h>    
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/wireless.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/powermemo.h>
#include "power.h"

extern powermemo_functions powermemofuncs;


#ifdef  CONFIG_DEVFS_FS
#include <linux/devfs_fs_kernel.h>
#endif

#define DEVNAME "power"
#define MAX_KPROBES 1

#define ENABLE_POWER_MEASUREMENT 	1
#define DISABLE_POWER_MEASUREMENT 	0

#define SUPPORT_UPROBE 			1
#define SUPPORT_SEQ_PROC		1
#define SUPPORT_PROBE_FUNC		1

#ifdef  CONFIG_DEVFS_FS
static devfs_handle_t devfs_handle;
#endif
int power_major = 200;

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp;
static struct kprobe endkp;
static struct kprobe *pkp;


#if SUPPORT_UPROBE
/*For each probe you need to allocate a uprobe structure*/
static struct uprobe p;
static struct uprobe endup;
static struct kretprobe retprobe;
#endif

int gstart = DISABLE_POWER_MEASUREMENT;

struct power_data {
  rwlock_t lock;
  unsigned char val;
};

struct kprobe_data {
  spinlock_t lock;
  struct file *file;
  struct list_head list;
  wait_queue_head_t wait;
  int type;
  struct power_cmd power;
  struct kprobe kp;
  struct kprobe end_kp;
  struct kretprobe kret;
}; 

struct kprobe_data kprobe_head;

#if SUPPORT_UPROBE
struct uprobe_data {
  spinlock_t lock;
  struct file *file;
  struct list_head list;
  wait_queue_head_t wait;
  int type;
  struct power_cmd power;
  struct uprobe up;
  struct uprobe end_up;
  struct kretprobe uret;
};

struct uprobe_data uprobe_head;
#endif

#define LOG_LOCKED  1
#define LOG_UNLOCKED    0
#define LOG_LOCK_SPIN_LIMIT 1000000
#define LOG_BUF_SIZE 100000
#define INTR_CONTEXT -1
#define COMMAND_BUFFER_LEN  2048
#define TIME_NOT_SET 0xffffffff

static unsigned int log_lock = LOG_UNLOCKED;

static atomic_t drop_count = ATOMIC_INIT(0);
static atomic_t lock_timeout_entry_count = ATOMIC_INIT(0);
static atomic_t lock_timeout_exit_count = ATOMIC_INIT(0);
static struct proc_dir_entry *powerlog_proc_file;

struct processor_u {
  unsigned long pid;
  char comm[TASK_COMM_LEN];
  unsigned long t_entry; /* entry time of the time slice */
  unsigned long t_exit; /* exit time of the time slice */
  long delta;
  char func_name[32];	
};
static struct processor_u log_buf[LOG_BUF_SIZE];
unsigned long log_next = 0;

static size_t power_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos);
static size_t power_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos);
int power_open(struct inode *inode, struct file *filp);
int power_release(struct inode *inode, struct file *filp);
long power_ioctl (struct file *filp,
                     unsigned int cmd, unsigned long arg);

//extern int (*test_enter)(struct task_struct *, char *);
//extern int (*test_exit)(struct task_struct *, char *);

const struct file_operations power_fops = {
    //.ioctl 		=      	power_ioctl,
  .unlocked_ioctl=power_ioctl,
  .open=power_open,
  .release=power_release,
  .read=power_read,
  .write=power_write,
};

static struct timeval sync_tv;  //the time point synchronized with the PC+DAQ

unsigned long gettime(void)
{

    struct timeval tv;
    unsigned long diff;

    do_gettimeofday(&tv);

  /* calculate the time elapsed in granularity of 50 microseconds
     * since the module is loaded.
     * sync_tv is filled when the client triggers this device with an IOCTL call
     */
    diff =  (tv.tv_sec - sync_tv.tv_sec)* 20000 +
            (tv.tv_usec - sync_tv.tv_usec) / 50;
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
int process_slice_enter(struct kprobe *p, struct pt_regs *regs)
{
  int lock_held_count;
  struct processor_u* entry;
  unsigned long flags;

  if (gstart != ENABLE_POWER_MEASUREMENT)
    return 0; 

  local_irq_save(flags);

  /* acquire lock on trace log */
  lock_held_count = 0;
  while( (cmpxchg(&log_lock, LOG_UNLOCKED, LOG_LOCKED)) == LOG_LOCKED ) {
    lock_held_count++;
    if (lock_held_count >= LOG_LOCK_SPIN_LIMIT ) {
      atomic_inc(&lock_timeout_entry_count);
      local_irq_restore(flags);
      return 0;
      }
    }
	
  if (log_next >= LOG_BUF_SIZE-1) {
    log_lock = LOG_UNLOCKED;
    return 0;
  }

  printk("=>enter pid: %d comm:%s time:0x%lu\n", current->pid, current->comm, gettime());
  entry = &log_buf[log_next++];
  entry->pid = in_interrupt() ? INTR_CONTEXT : current->pid;
  if (in_interrupt())
    strcpy(entry->comm, "intct");
  else
    strncpy(entry->comm, current->comm, TASK_COMM_LEN-1);
  entry->t_entry = gettime();
  entry->delta = TIME_NOT_SET;
  #if SUPPORT_PROBE_FUNC
  strcpy(entry->func_name, p->func_name);
  #endif
  log_lock = LOG_UNLOCKED;
  local_irq_restore(flags);
  return 0;
}

int process_slice_exit(struct kprobe *p, struct pt_regs *regs)
{
  unsigned int pid;
  int lock_held_count;
  int entry_i = -1;
  int i = 0;
  struct processor_u* entry = NULL;
  unsigned long flags;


  if (gstart != ENABLE_POWER_MEASUREMENT)
    return 0; 

  local_irq_save(flags);

  pid = in_interrupt() ? INTR_CONTEXT : current->pid;

  /* acquire lock on trace log */
  lock_held_count = 0;
  while( (cmpxchg(&log_lock, LOG_UNLOCKED, LOG_LOCKED))==LOG_LOCKED ) {
    lock_held_count++;
    if (lock_held_count >= LOG_LOCK_SPIN_LIMIT ) {
      atomic_inc(&lock_timeout_exit_count);
		local_irq_restore(flags);
      return 0;
    }
  }

  /* find matching entry in log - searching backwards from current log end */
  /* FIXTHIS - need lock on next_entry here */
  entry_i = -1;
  for (i = log_next-1; i >= 0; i--) {
    entry = &log_buf[i];
    if (entry->pid == pid &&
#if SUPPORT_PROBE_FUNC			
          entry->delta == TIME_NOT_SET && (strcmp(entry->func_name, p->func_name) == 0)) {
#else
			entry->delta == TIME_NOT_SET /*&& (strcmp(entry->func_name, p->func_name) == 0)*/) {
#endif
        entry_i = i;
        break;
      }
    }

    if (entry_i == -1 || entry == NULL) {
      log_lock = LOG_UNLOCKED;
      local_irq_restore(flags);
      return 0;
    }
    printk("exit=> pid: %d comm:%s time:0x%lu\n", current->pid, current->comm, gettime());

    entry->t_exit = gettime();
    entry->delta = entry->t_exit - entry->t_entry;	
    log_lock = LOG_UNLOCKED;
    local_irq_restore(flags);
    return 0;
}
int process_test_enter(struct task_struct *task, char *func_name)
{
    int lock_held_count;
    struct processor_u* entry;

	if (gstart != ENABLE_POWER_MEASUREMENT)
		return 0; 
	
    /* acquire lock on trace log */
    lock_held_count = 0;
    while( (cmpxchg(&log_lock, LOG_UNLOCKED, LOG_LOCKED)) == LOG_LOCKED ) {
        lock_held_count++;
        if (lock_held_count >= LOG_LOCK_SPIN_LIMIT ) {
            atomic_inc(&lock_timeout_entry_count);
            return 0;
        }
    }
	
	if (log_next >= LOG_BUF_SIZE-1) {
		log_lock = LOG_UNLOCKED;
		return 0;
	}
	
	//printk("=>enter pid: %d comm:%s time:0x%lu\n", task->pid, task->comm, gettime());
	entry = &log_buf[log_next++];
	entry->pid = in_interrupt() ? INTR_CONTEXT : task->pid;
	if (in_interrupt())
		strcpy(entry->comm, "intct");
	else
		strncpy(entry->comm, task->comm, TASK_COMM_LEN-1);
	entry->t_entry = gettime();
	entry->delta = TIME_NOT_SET;
	if (func_name != NULL)
		strcpy(entry->func_name, func_name);

	log_lock = LOG_UNLOCKED;
	return 0;
}

int process_test_exit(struct task_struct *task, char *func_name)
{
	unsigned int pid;
	int lock_held_count;
	int entry_i = -1;
	int i = 0;
	struct processor_u* entry = NULL;


	if (gstart != ENABLE_POWER_MEASUREMENT)
		return 0; 

	pid = in_interrupt() ? INTR_CONTEXT : task->pid;

    /* acquire lock on trace log */
    lock_held_count = 0;
    while( (cmpxchg(&log_lock, LOG_UNLOCKED, LOG_LOCKED)) == LOG_LOCKED ) {
        lock_held_count++;
        if (lock_held_count >= LOG_LOCK_SPIN_LIMIT ) {
            atomic_inc(&lock_timeout_exit_count);
            return 0;
        }
    }
	
    /* find matching entry in log - searching backwards from current log end */
    /* FIXTHIS - need lock on next_entry here */
    entry_i = -1;
    for (i = log_next-1; i >= 0; i--) {
        entry = &log_buf[i];
        if (entry->pid == pid &&
#if SUPPORT_PROBE_FUNC
            entry->delta == TIME_NOT_SET && (strcmp(entry->func_name, func_name) == 0)) {
#else
			entry->delta == TIME_NOT_SET ) {
#endif
            entry_i = i;
            break;
        }
    }

    if (entry_i == -1 || entry == NULL) {
        log_lock = LOG_UNLOCKED;
        return 0;
    }
	//printk("exit=> pid: %d comm:%s time:0x%lu\n", task->pid, task->comm, gettime());

	entry->t_exit = gettime();
	entry->delta = entry->t_exit - entry->t_entry;	
	log_lock = LOG_UNLOCKED;
	
	return 0;
}

int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk("\nkprobes => pre_handler:\n");
    /* dump_stack(); */
    /* It must return 0 in normal case */
    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    //printk("\nkprobes => post_handler: p->addr=0x%p, task_name = %s timestamp = %x\n",
    //    p->addr, current->comm, current->timestamp);
}

/* 
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 *    
 */
int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    //printk("kprobes => fault_handler: p->addr=0x%p, trap #%dn",
    //    p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

int end_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    printk("\nend kprobes => pre_handler\n");
    /* dump_stack(); */
    /* It must return 0 in normal case */
    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
void end_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    //printk("\nkprobes => post_handler: p->addr=0x%p, task_name = %s timestamp = %x\n",
    //    p->addr, current->comm, current->timestamp);
}

/* 
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 *    
 */
int end_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    //printk("kprobes => fault_handler: p->addr=0x%p, trap #%dn",
    //    p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}


/* uprobe pre_handler: called just before the probed instruction is executed */
int uprobe_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	//printk("uprobe_handler_pre\n");
    powermemofuncs.markerfunc_entry(current->pid, p->vaddr, p->func_name);
    return 0;
}

/* uprobe post_handler: called after the probed instruction is executed */
void uprobe_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
  //  printk("uprobes => post_handler: p->addr=0x%p, task_name = %s timestamp = %x\n",
  //      p->addr, current->comm, current->timestamp);
}

/* 
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
int uprobe_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
  //  printk("uprobes => fault_handler: p->addr=0x%p, trap #%dn",
  //      p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

/* uprobe pre_handler: called just before the probed instruction is executed */
int end_uprobe_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    //printk("\nuprobes => end pre_handler\n");
	powermemofuncs.markerfunc_exit(current->pid, p->vaddr, p->func_name);
    return 0;
}

/* uprobe post_handler: called after the probed instruction is executed */
void end_uprobe_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
   // printk("uprobes => post_handler: p->addr=0x%p, task_name = %s timestamp = %x\n",
   //     p->addr, current->comm, current->timestamp);
}

/* 
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
int end_uprobe_handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    //printk("uprobes => fault_handler: p->addr=0x%p, trap #%dn",
    //    p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

static char ret_func_name[NAME_MAX] = "schedule_probe";

/* per-instance private data */
struct my_data {
    ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	#if 1

	int pid = 0;

	pid = in_interrupt() ? INTR_CONTEXT : current->pid;
	//printk("pid = %d comm= %s func= %s\n", current->pid, current->comm, ri->rp->up.kp.func_name);
	powermemofuncs.markerfunc_entry(pid, ri->rp->up.kp.vaddr, ri->rp->up.kp.func_name);
    return 0;

	#else
    struct my_data *data;
	int pid = 0;

    if (!current->mm)
        return 1;   /* Skip kernel threads */
	pid = in_interrupt() ? INTR_CONTEXT : current->pid;
	//powermemofuncs.markerfunc_entry(pid, ri->rp->up.kp.vaddr, ri->rp->up.kp.func_name);
	//printk("pid = %d comm= %s\n", current->pid, current->comm);
    data = (struct my_data *)ri->data;
    data->entry_stamp = ktime_get();
    return 0;
	#endif
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	#if 1
	int pid = 0;
	
	pid = in_interrupt() ? INTR_CONTEXT : current->pid;
	powermemofuncs.markerfunc_exit(current->pid, ri->rp->up.kp.vaddr, ri->rp->up.kp.func_name);
    return 0;
	#else
	int pid = 0;
    int retval = regs_return_value(regs);
    struct my_data *data = (struct my_data *)ri->data;
    s64 delta;
    ktime_t now;
	
	pid = in_interrupt() ? INTR_CONTEXT : current->pid;
	//powermemofuncs.markerfunc_exit(current->pid, ri->rp->up.kp.vaddr, ri->rp->up.kp.func_name);
    now = ktime_get();
    delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
    printk(KERN_INFO "%s takes %lld ns\n",
            ri->rp->up.kp.func_name, (long long)delta);
    return 0;
	
	#endif
}

static struct kretprobe my_kretprobe = {
    .handler        = ret_handler,
    .entry_handler      = entry_handler,
    .data_size      = sizeof(struct my_data),
    /* Probe up to 20 instances concurrently. */
    .maxactive      = 20,
};

/*
 * Jumper probe for do_fork.
 * Mirror principle enables access to arguments of the probed routine
 * from the probe handler.
 */

/* Proxy routine having the same arguments as actual do_fork() routine */
static long jdo_fork(unsigned long clone_flags, unsigned long stack_start,
          struct pt_regs *regs, unsigned long stack_size,
          int __user *parent_tidptr, int __user *child_tidptr)
{
    printk(KERN_INFO "jprobe: clone_flags = 0x%lx, stack_size = 0x%lx,"
            " regs = 0x%p\n",
           clone_flags, stack_size, regs);

    /* Always end with a call to jprobe_return(). */
    jprobe_return();
    return 0;
}
void jschedule_probe(struct task_struct *cur, struct task_struct *next)
{
	printk("cur name %s next name %s\n", cur->comm, next->comm);
	return;
}

static struct jprobe my_jprobe = {
    .entry          = jschedule_probe,
    .kp = {
        .symbol_name    = "schedule_probe",
    },
};
static struct kprobe kppp = {
    .symbol_name    = "schedule_probe",
};

void kprobe_data_free(void)
{
	struct list_head *listptr = NULL;
	struct kprobe_data *entry = NULL;
	struct power_cmd *power = NULL;

	list_for_each(listptr, &kprobe_head.list) {
		entry = list_entry(listptr, struct kprobe_data, list);
		power = &entry->power;
		if (power) {
			printk("kprobe_data_free: Type:%d\n", entry->type);
			printk("kprobe_data_free: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n", 
									power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line, 
									power->end_line, power->line, power->action); 
		}
		kfree(entry);
	}
}
void kprobe_data_show(void)
{
	struct list_head *listptr;
	struct kprobe_data *entry;
	struct power_cmd *power = NULL;

	power = &kprobe_head.power;
	if (power)
	{
		printk("===================================\n");
		printk("kprobe_data_show: Type:%d\n", kprobe_head.type);
		printk("kprobe_data_show: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
	}

	list_for_each(listptr, &kprobe_head.list) {
		entry = list_entry(listptr, struct kprobe_data, list);
		power = &entry->power;
		if (power) {
			printk("kprobe_data_show: Type:%d\n", entry->type);
        	printk("kprobe_data_show: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
		}
	}
}
void kprobe_data_remove(struct kprobe_data *entry)
{
	struct power_cmd *power = NULL;

	if(entry == NULL){
		printk("kprobe_data_remove: Invalid kprobe data entry\n");
		return;
	}
	power = &entry->power;
	if (power) {
		printk("kprobe_data_remove: Type:%d\n", entry->type);
		printk("kprobe_data_remove: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
	}
	list_del(&entry->list);       /* Delete entry */
	kfree(entry);               /* free! */
}
struct kprobe_data * kprobe_data_add (int type, struct power_cmd *power_data, struct kprobe *kp, struct kprobe *endkp, struct kretprobe *kret)
{
	struct kprobe_data *ptr;

	if (!power_data)
	{
		printk("can't add power data to kprobe list\n");
		return NULL;
	}
	if (type == SINGLE_PROBE && !kp)
	{
		printk("can't add kprobe data to kprobe list\n");
		return NULL;
	}
	if (type == DUAL_PROBE && (!kp || !endkp))
	{
		printk("can't add dual kprobes data to kprobe list\n");
		return NULL;
	}
	if (type == RET_PROBE && !kret)
	{
		printk("can't add retkprobe data to kprobe list\n");
		return NULL;
	}		

	ptr = kmalloc(sizeof(struct kprobe_data), GFP_KERNEL);	
	if (ptr) {
		if (type == SINGLE_PROBE){
			memcpy(&ptr->kp, kp, sizeof(struct kprobe));
		}else if (type == DUAL_PROBE){
			memcpy(&ptr->kp, kp, sizeof(struct kprobe));
			memcpy(&ptr->end_kp, endkp, sizeof(struct kprobe));		
		}else if (type == RET_PROBE){
			memcpy(&ptr->kret, kret, sizeof(struct kretprobe));
		}
		memcpy(&ptr->power, power_data, sizeof(struct power_cmd));
		ptr->type = type;
		list_add(&ptr->list, &kprobe_head.list);
		return ptr; 
	}
	return NULL;
}

struct kprobe_data *kprobe_data_find(int type, int address, int start_address, int end_address)
{
    struct list_head *listptr = NULL;
    struct kprobe_data *entry = NULL;
    struct power_cmd *power = NULL;

    list_for_each(listptr, &kprobe_head.list) {
        entry = list_entry(listptr, struct kprobe_data, list);
        if (entry) {           
        	power = &entry->power;    
			if (power) {
				//printk("kprobe_data_remove: Type:%d\n", entry->type);
				//printk("kprobe_data_remove: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                //                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                //                    power->end_line, power->line, power->action);

				if (type == DUAL_PROBE) {
					if (power->start_address == start_address && power->end_address == end_address)
						return entry;			
				}else {
					if (power->address == address)
						return entry;
				}
    		}
        }
    }
	return NULL;
}
#if SUPPORT_UPROBE
void uprobe_data_free(void)
{
	struct list_head *listptr = NULL;
	struct uprobe_data *entry = NULL;
	struct power_cmd *power = NULL;

	list_for_each(listptr, &uprobe_head.list) {
		entry = list_entry(listptr, struct uprobe_data, list);
		power = &entry->power;
		if (power) {
			printk("uprobe_data_free: Type:%d\n", entry->type);
			printk("uprobe_data_free: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n", 
									power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line, 
									power->end_line, power->line, power->action); 
		}
		kfree(entry);
	}
}
void uprobe_data_show(void)
{
	struct list_head *listptr;
	struct uprobe_data *entry;
	struct power_cmd *power = NULL;

	power = &uprobe_head.power;
	if (power)
	{
		printk("===================================\n");
		printk("uprobe_data_show: Type:%d\n", uprobe_head.type);
		printk("uprobe_data_show: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
	}

	list_for_each(listptr, &uprobe_head.list) {
		entry = list_entry(listptr, struct uprobe_data, list);
		power = &entry->power;
		if (power) {
			printk("uprobe_data_show: Type:%d\n", entry->type);
        	printk("uprobe_data_show: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
		}
	}
}
void uprobe_data_remove(struct uprobe_data *entry)
{
	struct power_cmd *power = NULL;

	if(entry == NULL){
		printk("uprobe_data_remove: Invalid uprobe data entry\n");
		return;
	}
	power = &entry->power;
	#ifdef PROBEDBG
	if (power) {
		printk("uprobe_data_remove: Type:%d\n", entry->type);
		printk("uprobe_data_remove: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
	}
	#endif
	list_del(&entry->list);       /* Delete entry */
	kfree(entry);               /* free! */
}
struct uprobe_data * uprobe_data_add (int type, struct power_cmd *power_data, struct uprobe *up, struct uprobe *endup, struct kretprobe *uret)
{
	struct uprobe_data *ptr;

	if (!power_data)
	{
		printk("can't add power data to uprobe list\n");
		return NULL;
	}
	if (type == SINGLE_PROBE && !up)
	{
		printk("can't add uprobe data to uprobe list\n");
		return NULL;
	}
	if (type == DUAL_PROBE && (!up || !endup))
	{
		printk("can't add dual uprobes data to uprobe list\n");
		return NULL;
	}
	if (type == RET_PROBE && !uret)
	{
		printk("can't add retuprobe data to uprobe list\n");
		return NULL;
	}		

	ptr = kmalloc(sizeof(struct uprobe_data), GFP_KERNEL);	
	if (ptr) {
		if (type == SINGLE_PROBE){
			memcpy(&ptr->up, up, sizeof(struct uprobe));
		}else if (type == DUAL_PROBE){
			memcpy(&ptr->up, up, sizeof(struct uprobe));
			memcpy(&ptr->end_up, endup, sizeof(struct uprobe));		
		}else if (type == RET_PROBE) {
			memcpy(&ptr->uret, uret, sizeof(struct kretprobe));
		}
		memcpy(&ptr->power, power_data, sizeof(struct power_cmd));
		ptr->type = type;
		list_add(&ptr->list, &uprobe_head.list);
		return ptr; 
	}
	return NULL;
}

struct uprobe_data *uprobe_data_find(int type, int address, int start_address, int end_address)
{
    struct list_head *listptr = NULL;
    struct uprobe_data *entry = NULL;
    struct power_cmd *power = NULL;

    list_for_each(listptr, &uprobe_head.list) {
        entry = list_entry(listptr, struct uprobe_data, list);
		if (entry) {
        	power = &entry->power;           
			if (power) {
				#ifdef PROBEDBG
				printk("uprobe_data_find: Type:%d\n", entry->type);
				printk("uprobe_data_find: file:%s, func:%s, addr:0x%x, startaddr:0x%x, endaddr:0x%x, startline:%d, endline:%d, line:%d, act:%d\n",
                                    power->filename, power->function, power->address, power->start_address, power->end_address, power->start_line,
                                    power->end_line, power->line, power->action);
				#endif
				if (type == DUAL_PROBE) {
					if (power->start_address == start_address && power->end_address == end_address)
						return entry;			
				}else {
					if (power->address == address)
						return entry;
				}
    		}
        }
    }
	return NULL;
}
#endif
int power_open(struct inode *inode, struct file *filp)
{
	struct power_data *dev = NULL;

	printk("power_open\n");

	dev = kmalloc(sizeof(struct power_data), GFP_KERNEL);
	if (dev == NULL) {
		printk("No Available Memory !!!\n");
		return -ENOMEM;
	}

	rwlock_init(&dev->lock);
	dev->val = 0x99;

	filp->private_data = dev;

	return 0;
}

int power_release(struct inode *inode, struct file *filp)
{
	struct power_data *dev = filp->private_data;

	printk("power_release\n");

	if (dev) {
		kfree(dev);
	}

	return 0;
}

size_t power_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	struct power_data *dev = filp->private_data;
	unsigned char val;
	int retval;
	int i; 

	read_lock(&dev->lock);
	val = dev->val;
	read_unlock(&dev->lock);

	for (i = 0; i < count; i++) {
		if (copy_to_user(&buf[i], &val, 1)) {
			retval = -EFAULT;
			goto out;
		}
	}
	retval = count;
out:
	return retval;
}

size_t power_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{

	return 0;
}
int functionblockid = 0;
long power_ioctl (struct file *filp,
                     unsigned int cmd, unsigned long arg)
{
	char tmp_str[32];
	int retval = 0;
	struct kprobe_data *pentry = NULL;
	#if SUPPORT_UPROBE	
	struct nameidata nd;
	struct uprobe_data *puentry = NULL;
	#endif
	struct power_data *dev = filp->private_data;
	struct power_cmd data;
	char *ptest = NULL;
	struct processor_u *pru = NULL;
	int ret = 0;
	int i = 0;
	unsigned long flags;
	char *path_prefix[] = {"/data/powermemo/","/data/powermemo/lmbench/bin/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/system/bin/", "/system/xbin/"};	
	int tpath = sizeof(path_prefix)/sizeof(char *);
	
	//printk("power_ioctl: cmd = 0x%x\n", cmd);
	switch (cmd)
	{
		case REGISTER_KPROBE_CMD_SHOW:
			break;

		case REGISTER_KPROBE_CMD:
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("register kprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			printk("line: %d\n", data.line);
			printk("action: %d\n", data.action);
			#endif
			pentry = kprobe_data_find(SINGLE_PROBE, data.address, data.start_address, data.end_address);

			if (pentry != NULL) {
				printk("the kprobe is registered\n");
				return retval;
			}	
			kp.pre_handler = handler_pre;
            kp.post_handler = handler_post;
            kp.fault_handler = handler_fault;
            kp.addr = (kprobe_opcode_t *)data.address;
    		/* register the kprobe now */
        	if (!kp.addr) {
        		printk("Couldn't find %s:0x%x to plant kprobe\n", data.function, data.address);
        		return -1;
    		}
			pentry = kprobe_data_add(SINGLE_PROBE, &data, &kp, NULL, NULL);
			if (pentry == NULL) {
                printk("can't insert kprobe, memory is full\n");
                return -1;
            }
               	
			if ((ret = register_kprobe(&pentry->kp) < 0)) {
       			printk("register_kprobe failed, returned %d\n", ret);
        		return -1;
    		}
			break;

		case UNREGISTER_KPROBE_CMD:
            if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
                retval = -EFAULT;
                goto done;
            }
			#ifdef PROBEDBG
            printk("unregister kprobe:\n");
            printk("file name: %s\n", data.filename);
            printk("function: %s\n", data.function);
            printk("address: 0x%x\n", data.address);
            printk("line: %d\n", data.line);
            printk("action: %d\n", data.action);
			#endif	
            pentry = kprobe_data_find(SINGLE_PROBE, data.address, data.start_address, data.end_address);

            if (pentry == NULL) {
                printk("the kprobe is not registered\n");
                return retval;
            }

        	unregister_kprobe(&pentry->kp);
			kprobe_data_remove(pentry);
			break;
		#if SUPPORT_UPROBE
		case REGISTER_UPROBE_CMD_SHOW:
			break;

		case REGISTER_UPROBE_CMD:
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
                retval = -EFAULT;
                goto done;
            }
			#ifdef PROBEDBG
            printk("register uprobe:\n");
            printk("file name: %s\n", data.filename);
            printk("function: %s\n", data.function);
            printk("address: 0x%x\n", data.address);
            printk("line: %d\n", data.line);
            printk("action: %d\n", data.action);
			printk("image: %s\n", data.image);
			#endif 
			puentry = uprobe_data_find(SINGLE_PROBE, data.address, data.start_address, data.end_address);

			if (puentry != NULL) {
				printk("the uprobe is registered\n");
				return retval;
			}	

			p.pathname = kmalloc(32, GFP_KERNEL);
			for (i = 0; i < tpath; i++) {
				sprintf(p.pathname, "%s%s", path_prefix[i], data.image);
	    		if ((retval = path_lookup(p.pathname, LOOKUP_FOLLOW, &nd)) == 0) break;        			
    		}
			if (retval != 0){
				printk("Invalid image name, path lookup fail\n");
				return -1;
			}
			p.kp.pre_handler = uprobe_handler_pre;
			p.kp.post_handler = uprobe_handler_post;
			p.kp.fault_handler = uprobe_handler_fault;
			p.kp.addr = (kprobe_opcode_t *)data.address;
			p.offset = (unsigned long)data.address - 0x00008000;
			/* register the kprobe now */
			if (!p.kp.addr) {
				printk("Couldn't find %s to plant kprobe\n", "do_fork");
				return -1;
			}

			puentry = uprobe_data_add(SINGLE_PROBE, &data, &p, NULL, NULL);
			if (puentry == NULL) {
                printk("can't insert uprobe, memory is full\n");
				kfree(p.pathname);
                return -1;
            }

			if ((ret = register_uprobe(&puentry->up) < 0)) {
				printk("register_uprobe failed, returned %d\n", ret);
				kfree(p.pathname);
				return -1;
			}
			kfree(p.pathname);

			break;

		case UNREGISTER_UPROBE_CMD:
            if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
                retval = -EFAULT;
                goto done;
            }
			#ifdef PROBEDBG
            printk("unregister uprobe:\n");
            printk("file name: %s\n", data.filename);
            printk("function: %s\n", data.function);
            printk("address: 0x%x\n", data.address);
            printk("line: %d\n", data.line);
            printk("action: %d\n", data.action);
			#endif
			puentry = uprobe_data_find(SINGLE_PROBE, data.address, data.start_address, data.end_address);

			if (puentry == NULL) {
				printk("the kprobe is not registered\n");
				return retval;
			}

			unregister_uprobe(&puentry->up);
			uprobe_data_remove(puentry);
			break;
		#endif
		case REGISTER_DUAL_KPROBE_CMD:
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("register dual kprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			printk("start address: 0x%x\n", data.start_address);
			printk("end address: 0x%x\n", data.end_address);
			printk("line: %d\n", data.line);
			printk("start line: %d\n", data.start_line);
			printk("end line: %d\n", data.end_line);
			printk("action: %d\n", data.action);
			#endif
			pentry = kprobe_data_find(DUAL_PROBE, data.address, data.start_address, data.end_address);

			if (pentry != NULL) {
				printk("the kprobe is registered\n");
				return retval;
			}	
		
			kp.pre_handler = handler_pre;
            kp.post_handler = handler_post;
            kp.fault_handler = handler_fault;
            kp.addr = (kprobe_opcode_t *)data.start_address;
			#if SUPPORT_PROBE_FUNC
			strcpy(kp.func_name, data.function);
			#endif
    		/* register the kprobe now */
        	if (!kp.addr) {
        		printk("Couldn't find %s:0x%x to plant kprobe\n", data.function, data.start_address);
        		return -1;
    		}

            endkp.pre_handler = end_handler_pre;
            endkp.post_handler = end_handler_post;
            endkp.fault_handler = end_handler_fault;
            endkp.addr = (kprobe_opcode_t *)data.end_address;
			#if SUPPORT_PROBE_FUNC
			strcpy(endkp.func_name, data.function);
			#endif
            /* register the kprobe now */
            if (!endkp.addr) {
                printk("Couldn't find %s:0x%x to plant kprobe\n", data.function, data.end_address);
                return 0;
            }

			pentry = kprobe_data_add(DUAL_PROBE, &data, &kp, &endkp, NULL);
			if (pentry == NULL) {
                printk("can't insert kprobe, memory is full\n");
                return 0;
            }
               	
			if ((ret = register_kprobe(&pentry->kp) < 0)) {
       			printk("register start kprobe failed, returned %d\n", ret);
        		return 0;
    		}
			
			if ((ret = register_kprobe(&pentry->end_kp) < 0)) {
				unregister_kprobe(&pentry->kp);
       			printk("register end kprobe failed, returned %d\n", ret);
        		return 0;
    		}

        	//printk("dual kprobe registered %d\n", 0);
			break;
		case UNREGISTER_DUAL_KPROBE_CMD:
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("unregister dual kprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			printk("start address: 0x%x\n", data.start_address);
			printk("end address: 0x%x\n", data.end_address);
			printk("line: %d\n", data.line);
			printk("start line: %d\n", data.start_line);
			printk("end line: %d\n", data.end_line);
			printk("action: %d\n", data.action);
			#endif
			pentry = kprobe_data_find(DUAL_PROBE, data.address, data.start_address, data.end_address);

            if (pentry == NULL) {
                printk("the kprobe is not registered\n");
                return retval;
            }

        	unregister_kprobe(&pentry->kp);
			unregister_kprobe(&pentry->end_kp);
			kprobe_data_remove(pentry);

			break;
		#if SUPPORT_UPROBE	
		case REGISTER_DUAL_UPROBE_CMD:
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("register dual uprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			printk("start address: 0x%x\n", data.start_address);
			printk("end address: 0x%x\n", data.end_address);
			printk("line: %d\n", data.line);
			printk("start line: %d\n", data.start_line);
			printk("end line: %d\n", data.end_line);
			printk("action: %d\n", data.action);
			printk("image: %s\n", data.image);
			#endif
			puentry = uprobe_data_find(DUAL_PROBE, data.address, data.start_address, data.end_address);

			if (puentry != NULL) {
				printk("the dual uprobe is registered\n");
				return retval;
			}	
			p.pathname = kmalloc(32, GFP_KERNEL);
			for (i = 0; i < tpath; i++) {
				sprintf(p.pathname, "%s%s", path_prefix[i], data.image);
	    		if ((retval = path_lookup(p.pathname, LOOKUP_FOLLOW, &nd)) == 0) break;        			
    		}
			if (retval != 0){
				kfree(p.pathname);
				printk("Invalid image name, path lookup fail\n");
				return -1;
			}
			p.kp.pre_handler = uprobe_handler_pre;
			p.kp.post_handler = uprobe_handler_post;
			p.kp.fault_handler = uprobe_handler_fault;
			p.kp.addr = (kprobe_opcode_t *)data.start_address;
			//just for test
			p.kp.vaddr = functionblockid;
			#if SUPPORT_PROBE_FUNC
			sprintf(tmp_str, "%s:%d~%d", data.function, data.start_line, data.end_line);
			strcpy(p.kp.func_name, tmp_str);
			#endif
			p.offset = (unsigned long)(data.start_address - 0x8000);
			/* register the kprobe now */
			if (!p.kp.addr) {
				kfree(p.pathname);
				printk("Couldn't find %s to plant uprobe\n", "do_fork");
				return -1;
			}

			endup.pathname = kmalloc(32, GFP_KERNEL);
			for (i = 0; i < tpath; i++) {
				sprintf(endup.pathname, "%s%s", path_prefix[i], data.image);
	    		if ((retval = path_lookup(endup.pathname, LOOKUP_FOLLOW, &nd)) == 0) break;        			
    		}
			if (retval != 0){
				kfree(endup.pathname);
				printk("Invalid image name, path lookup fail\n");
				return -1;
			}

			endup.kp.pre_handler = end_uprobe_handler_pre;
			endup.kp.post_handler = end_uprobe_handler_post;
			endup.kp.fault_handler = end_uprobe_handler_fault;
			endup.kp.addr = (kprobe_opcode_t *)data.end_address;
			endup.kp.vaddr = functionblockid;
			functionblockid++;
			#if SUPPORT_PROBE_FUNC
			sprintf(tmp_str, "%s:%d~%d", data.function, data.start_line, data.end_line);
			strcpy(endup.kp.func_name, tmp_str);
			#endif
			endup.offset = (unsigned long)(data.end_address - 0x8000);
			/* register the kprobe now */
			if (!endup.kp.addr) {
				kfree(endup.pathname);
				printk("Couldn't find %s to plant uprobe\n", "do_fork");
				return -1;
			}

			puentry = uprobe_data_add(DUAL_PROBE, &data, &p, &endup, NULL);
			if (puentry == NULL) {
				kfree(endup.pathname);
				printk("can't insert uprobe, memory is full\n");
                return -1;
            }
    		
			if ((ret = register_uprobe(&puentry->up) < 0)) {
				kfree(p.pathname);
				kfree(endup.pathname);
       			printk("register start uprobe failed, returned %d\n", ret);
        		return -1;
    		}
			
			if ((ret = register_uprobe(&puentry->end_up) < 0)) {
				kfree(p.pathname);
				kfree(endup.pathname);
       			printk("register end uprobe failed, returned %d\n", ret);
        		return -1;
    		}
			kfree(p.pathname);
			kfree(endup.pathname);
			break;

		case UNREGISTER_DUAL_UPROBE_CMD:
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("unregister dual uprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			printk("start address: 0x%x\n", data.start_address);
			printk("end address: 0x%x\n", data.end_address);
			printk("line: %d\n", data.line);
			printk("start line: %d\n", data.start_line);
			printk("end line: %d\n", data.end_line);
			printk("action: %d\n", data.action);
			#endif
			puentry = uprobe_data_find(DUAL_PROBE, data.address, data.start_address, data.end_address);

            if (puentry == NULL) {
                printk("the uprobe is not registered\n");
                return retval;
            }

        	unregister_uprobe(&puentry->up);
			unregister_uprobe(&puentry->end_up);
			uprobe_data_remove(puentry);

			break;
		#endif
		case REGISTER_SCHEDULE_CMD:
		{
			int ret;

			printk("Receive Register Schedule Command\n");	
			kppp.pre_handler = handler_pre;
			
			ret = register_kprobe(&kppp);
			if (ret < 0) {
				printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
				return ret;
			}
			printk(KERN_INFO "Planted kprobe at %p\n", kppp.addr);
			break;
		}
		case UNREGISTER_SCHEDULE_CMD:
		{
			printk("Receive UnRegister Schedule Command\n");			
			unregister_kprobe(&kppp);
			printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);

			break;
		}
		case REGISTER_FUNCTION_KPROBE_CMD:
			//printk("Receive Register Function kprobe Command\n");

			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
                retval = -EFAULT;
                goto done;
            }
			#ifdef PROBEDBG
            printk("register kretprobe:\n");
            printk("file name: %s\n", data.filename);
            printk("function: %s\n", data.function);
            printk("address: 0x%x\n", data.address);
			#endif
			puentry = kprobe_data_find(RET_PROBE, data.address, data.start_address, data.end_address);

			if (puentry != NULL) {
				printk("the kretprobe is registered\n");
				return retval;
			}	
			memset(&retprobe, 0, sizeof(struct kretprobe));
			retprobe.handler = ret_handler;
			retprobe.entry_handler = entry_handler;
			retprobe.data_size = sizeof(struct my_data);
			retprobe.maxactive = 20;
			retprobe.kp.addr = data.address;
			
			//just for test
			retprobe.kp.vaddr = functionblockid;
			strcpy(retprobe.kp.func_name, data.function);

			pentry = kprobe_data_add(RET_PROBE, &data, NULL, NULL, &retprobe);

			if (pentry == NULL) {
				printk("can't add KRETPROBE\n");
                return -1;
            } 		
			if ((ret = register_kretprobe(&pentry->kret) < 0)) {
       			printk("register kretuprobe failed, returned %d\n", ret);
        		return -1;
    		}
			if (ret < 0) {
				printk(KERN_INFO "register_kretprobe failed, returned %d\n",
						ret);
				return -1;
			}
			functionblockid++;
			//printk(KERN_INFO "register kretprobe at: %p\n", retprobe.kp.addr);
			
			break;
		case UNREGISTER_FUNCTION_KPROBE_CMD:
			//printk("Receive UnRegister Function kprobe Command\n");
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("unregister kretprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			#endif
			
			pentry = kprobe_data_find(RET_PROBE, data.address, 0, 0);

            if (pentry == NULL) {
                printk("the kretprobe is not registered\n");
                return retval;
            }

        	unregister_kretprobe(&pentry->kret);
			uprobe_data_remove(pentry);

			break;
		case REGISTER_FUNCTION_UPROBE_CMD:
			//printk("Receive Register Function Uprobes Command\n");
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
                retval = -EFAULT;
                goto done;
            }
			#ifdef PROBEDBG
            printk("register uretprobe:\n");
            printk("file name: %s\n", data.filename);
            printk("function: %s\n", data.function);
            printk("address: 0x%x\n", data.address);
			#endif
			puentry = uprobe_data_find(RET_PROBE, data.address, data.start_address, data.end_address);

			if (puentry != NULL) {
				printk("the uprobe is registered\n");
				return retval;
			}	
			memset(&retprobe, 0, sizeof(struct kretprobe));
			retprobe.up.pathname = kmalloc(32, GFP_KERNEL);
			for (i = 0; i < tpath; i++) {
				sprintf(retprobe.up.pathname, "%s%s", path_prefix[i], data.image);
	    		if ((retval = path_lookup(retprobe.up.pathname, LOOKUP_FOLLOW, &nd)) == 0) break;        			
    		}
			if (retval != 0){
				printk("Invalid image name, path lookup fail\n");
				return -1;
			}
			retprobe.handler = ret_handler;
			retprobe.entry_handler = entry_handler;
			retprobe.data_size = sizeof(struct my_data);
			retprobe.maxactive = 20;
			retprobe.up.kp.addr = data.address;
			retprobe.up.offset = data.address-0x8000;
			//just for test
			retprobe.up.kp.vaddr = functionblockid;
			strncpy(retprobe.up.kp.func_name, data.function, 31);

			puentry = uprobe_data_add(RET_PROBE, &data, NULL, NULL, &retprobe);

			if (puentry == NULL) {
				kfree(retprobe.up.pathname);
				printk("can't add URETPROBE\n");
                return -1;
            } 		
			if ((ret = register_uretprobe(&puentry->uret) < 0)) {
				kfree(retprobe.up.pathname);				
       			printk("register uretuprobe failed, returned %d\n", ret);
        		return -1;
    		}
			if (ret < 0) {
				kfree(retprobe.up.pathname);				
				printk(KERN_INFO "register_uretprobe failed, returned %d\n",
						ret);
				return -1;
			}
			functionblockid++;
			kfree(retprobe.up.pathname);				
			
			break;
		case UNREGISTER_FUNCTION_UPROBE_CMD:
			//printk("Receive Unregister Function Uprobes Command\n");			
			if (copy_from_user(&data, (int __user *)arg, sizeof(data))) {
				retval = -EFAULT;
				goto done;
			}
			#ifdef PROBEDBG
			printk("unregister uretprobe:\n");
			printk("file name: %s\n", data.filename);
			printk("function: %s\n", data.function);
			printk("address: 0x%x\n", data.address);
			#endif
			puentry = uprobe_data_find(RET_PROBE, data.address, 0, 0);

            if (puentry == NULL) {
                printk("the uprobe is not registered\n");
                return retval;
            }

        	unregister_uretprobe(&puentry->uret);
			uprobe_data_remove(puentry);
			break;
		case GET_MEASURE_RESULT_CMD:

			printk("get measure result cmd\n"); 
			if (copy_to_user((char __user *)arg, (char *)log_buf, sizeof(struct processor_u)*log_next)) {
				printk("get measure result fail\n");
				retval = -EFAULT;
				goto done;
			}
			retval = sizeof(struct processor_u)*log_next;
			printk("get measure result ok: %d\n", retval);
			break;
		default:
			printk("unknow power cmd\n");
			break;
	}

done:
	return retval;
}

#if SUPPORT_SEQ_PROC
static void *powerdbg_seq_start(struct seq_file *seq, loff_t *pos)
{
	return (*pos > LOG_BUF_SIZE || *pos > log_next || log_next < 0) ? NULL : pos;
}

static void *powerdbg_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= LOG_BUF_SIZE || *pos > log_next || log_next < 0)
		return NULL;
	return pos;
}

static void powerdbg_seq_stop(struct seq_file *seq, void *v)
{
	/* do nothing */
}

static int powerdbg_seq_show(struct seq_file *seq, void *v)
{
	unsigned int i = *(loff_t *) v;
	struct processor_u *task = NULL;

	task = &log_buf[i];

	if (task->delta <= 0)
	{
		return 0;
	}
	if (task->pid == 0)
	{
		seq_printf(seq, "%d,%s,%ld,%ld,%ld,%s\n", 
				task->pid, "idle", task->t_entry, task->t_exit, task->delta, task->func_name);
	}
	else
	{
		seq_printf(seq, "%d,%s,%ld,%ld,%ld,%s\n", 
				task->pid, task->comm, task->t_entry, task->t_exit, task->delta, task->func_name);
	}
	return 0;
}


static struct seq_operations powerdbg_seq_ops = {
	.start = powerdbg_seq_start,
	.next  = powerdbg_seq_next,
	.stop  = powerdbg_seq_stop,
	.show  = powerdbg_seq_show,
};

static int powerdbg_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &powerdbg_seq_ops);
}
static ssize_t powerdbg_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	unsigned long flags;
	char s[12];
	int i = 0;
	struct processor_u *run = NULL;

	memset(s, 0 , sizeof(s));
	if (!count)
		return 0;

	if (copy_from_user(s, buffer, count))
		return -EFAULT;

	printk("powerdbg_write:%s\n", s);
	
	local_irq_save(flags);
	if (strncmp(s, "start", 5) == 0) {
		printk("start power debug measurement\n");
		do_gettimeofday(&sync_tv);		
		//test_enter = process_test_enter;
		//test_exit = process_test_exit;		
		gstart = ENABLE_POWER_MEASUREMENT;
	} else if (strncmp(s, "stop", 4) == 0){
		printk("stop power debug measurement\n");
		//test_enter = NULL;
		//test_exit = NULL;
		gstart = DISABLE_POWER_MEASUREMENT;	
	} else if (strncmp(s, "clean", 5) == 0){
		memset(log_buf, 0, sizeof(struct processor_u)*LOG_BUF_SIZE);
		log_next = 0;
	} else if (strncmp(s, "dump", 4) == 0){

		run = log_buf;
		for(i = 0; i < log_next; i++)
			printk("%d.%s.%d.%x.%x.%s\n",
							run[i].pid, run[i].comm, run[i].delta, run[i].t_entry, run[i].t_exit, run[i].func_name);
	}
	local_irq_restore(flags);
		
	return count;
}

static const struct file_operations powerdbg_proc_fops = {
	.owner	 = THIS_MODULE,
	.open    = powerdbg_seq_open,
	.read    = seq_read,
	.write   = powerdbg_write,
	.llseek  = seq_lseek,
	.release = seq_release,
};

#else

#define dump_str(buf, len, fmt, arg...) \
    if (buf) len += sprintf(buf + len, fmt, ## arg); \
    else len += printk(KERN_EMERG fmt, ## arg)
		
static int dump_config(char *buf, struct processor_u *run)
{
	int i, len = 0;

	/* dump the log in format of "pid:process name:delta time:enter time:exit time:function name" */
	for (i = 0; i < log_next; i++ ) {
		dump_str(buf, len, "%d.%s.%d.%x.%x.%s\n",
				run[i].pid, run[i].comm, run[i].delta, run[i].t_entry, run[i].t_exit, run[i].func_name);
	}
	return len;
}

static int proc_read_powerlog(char *page, char **start, off_t off, int count, int *eof,
    void *data)
{
    int len;
    struct processor_u* run = log_buf;

    if (log_next == -1) {
        len = 0;
        dump_str(page, len, "No logging run registered\n");
    } else {
        len = dump_config(page, run);
    }
    return len;
}

static int proc_write_powerlog(struct file *file, const char *buffer,
		unsigned long count, void *data)
{
	static char cmd_buffer[COMMAND_BUFFER_LEN];

	if (count > COMMAND_BUFFER_LEN) {
		return -EINVAL;
	}

	/* FIXTHIS - do I need a verify_area() here? */
	if (copy_from_user(cmd_buffer, buffer, count)) {
		return -EFAULT;
	}
	cmd_buffer[count] = '\0';

	printk("%s\n", cmd_buffer);

	if (strcmp(cmd_buffer, "start") == 0) {
		gstart = ENABLE_POWER_MEASUREMENT;
		test_enter = process_test_enter;
		test_exit = process_test_exit;
	} else if (strcmp(cmd_buffer, "stop") == 0){
		gstart = DISABLE_POWER_MEASUREMENT;
		test_enter = NULL;
		test_exit = NULL;		
	}	
	return count;
}
#endif

static int power_init(void)
{

#ifdef  CONFIG_DEVFS_FS
    if(devfs_register_chrdev(power_major, DEVNAME , &power_fops)) {
		printk(KERN_WARNING " ps: can't create device node - ps\n");
		return -EIO;
    }

    devfs_handle = devfs_register(NULL, DEVNAME, DEVFS_FL_DEFAULT, power_major, 0, 
				S_IFCHR | S_IRUGO | S_IWUGO, &power_fops, NULL);
#else
    int result=0;

    result = register_chrdev(power_major, DEVNAME, &power_fops);
    if (result < 0) {
        printk(KERN_WARNING "ps: can't get major %d\n", power_major);
        return result;
    }

    if (power_major == 0) {
		power_major = result; /* dynamic */
    }
#endif
	
	/* init link list for register kprobe */
	memset(&kprobe_head, 0, sizeof(struct kprobe_data));
	INIT_LIST_HEAD(&kprobe_head.list);

	#if SUPPORT_UPROBE
	/* init link list for register kprobe */
	memset(&uprobe_head, 0, sizeof(struct uprobe_data));
	INIT_LIST_HEAD(&uprobe_head.list); 
	#endif
	
    powerlog_proc_file = create_proc_entry("powerdbg", 0644, NULL);

	if (powerlog_proc_file == NULL) {
		printk("create powerdbg proc entry fail\n");	
		return 0;
	}
	#if SUPPORT_SEQ_PROC
	powerlog_proc_file->proc_fops = &powerdbg_proc_fops;
	#else
	powerlog_proc_file->data = NULL;
	powerlog_proc_file->read_proc = proc_read_powerlog;
	powerlog_proc_file->write_proc = proc_write_powerlog;
	powerlog_proc_file->owner = THIS_MODULE;
	#endif
    printk("power_major = %d\n", power_major);
	
    return 0;
}

static void power_exit(void)
{
    printk("power_exit\n");

    remove_proc_entry("powerdbg", NULL);
#ifdef  CONFIG_DEVFS_FS
    devfs_unregister_chrdev(power_major, DEVNAME);
    devfs_unregister(devfs_handle);
#else
    unregister_chrdev(power_major, DEVNAME);
#endif
}

module_init(power_init);
module_exit(power_exit);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,12)
MODULE_PARM (power_major, "i");
#else
module_param (power_major, int, 0);
#endif

MODULE_LICENSE("GPL");
