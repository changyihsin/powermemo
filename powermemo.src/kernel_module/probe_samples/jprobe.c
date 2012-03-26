/*
 * Here's a sample kernel module showing the use of jprobes to dump
 * the arguments of do_fork().
 *
 * For more information on theory of operation of jprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the
 * console whenever do_fork() is invoked to create a new process.
 * (Some messages may be suppressed if syslogd is configured to
 * eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>


/*
 * Jumper probe for do_fork.
 * Mirror principle enables access to arguments of the probed routine
 * from the probe handler.
 */
int jnetif_receive_skb(struct sk_buff *skb)
{
	printk(KERN_INFO "jprobe: netif_receive_skb\n");

	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;

}

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

static struct jprobe my_jprobe = {
	.entry			= jdo_fork,
	.kp = {
		.symbol_name	= "do_fork",
	},
};

//static struct jprobe my_jprobe_netif = {
//	.entry			= jnetif_receive_skb,
//	.kp = {
//		.symbol_name	= "netif_receive_skb",
//	},
//};
asmlinkage void __sched jschedule(void)
{
    struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();
	int i = 0;

	printk("enter schedule\n");
	if(kcb != NULL)
	{
		printk("stack of schedule function\n");
		for (i = 0; i < MAX_JPROBES_STACK_SIZE; i++) {
			printk("%x ", kcb->jprobes_stack[i]);
			if(i%16 == 0) printk("\n");
		}
	}	
	jprobe_return();
}


static struct jprobe my_jprobe_netif = {
	.entry			= jschedule,
	.kp = {
		.symbol_name	= "schedule",
	},
};

static int __init jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&my_jprobe_netif);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
	       my_jprobe_netif.kp.addr, my_jprobe_netif.entry);
	return 0;
}

static void __exit jprobe_exit(void)
{
	unregister_jprobe(&my_jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
