/*
 * kretprobe_example.c
 *
 * Here's a sample kernel module showing the use of return probes to
 * report the return value and total time taken for probed function
 * to run.
 *
 * usage: insmod kretprobe_example.ko func=<func_name>
 *
 * If no func_name is specified, do_fork is instrumented
 *
 * For more information on theory of operation of kretprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the console
 * whenever the probed function returns. (Some messages may be suppressed
 * if syslogd is configured to eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>

#define MAX_FUNCS 50000

static char func_name[NAME_MAX] = "do_fork";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
			" function's execution time");

static int multi_addr[MAX_FUNCS];
static int multi_addr_num = 0;
module_param_array(multi_addr, int, &multi_addr_num, 0000);


/* per-instance private data */
struct my_data {
	ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct my_data *)ri->data;
	data->entry_stamp = ktime_get();
	return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct my_data *data = (struct my_data *)ri->data;
	s64 delta;
	ktime_t now;

	now = ktime_get();
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	printk(KERN_INFO "%s returned %d and took %lld ns to execute\n",
			func_name, retval, (long long)delta);
	return 0;
}

static struct kretprobe kretprobe[MAX_FUNCS];

static int __init kretprobe_init(void)
{
	int ret, i;

	for (i = 0; i < multi_addr_num; i++)
	{
		kretprobe[i].handler = ret_handler;
		kretprobe[i].entry_handler = entry_handler;
		kretprobe[i].data_size = sizeof(struct my_data);
		kretprobe[i].maxactive = 20;
		kretprobe[i].kp.addr = multi_addr[i];
		ret = register_kretprobe(&kretprobe[i]);
		if (ret < 0) {
			printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
			return -1;
		}
		printk(KERN_INFO "Planted return probe at %p\n",
				kretprobe[i].kp.addr);
	}
	return 0;
}

static void __exit kretprobe_exit(void)
{
	int i = 0;

	for (i = 0; i < multi_addr_num; i++)
	{
		unregister_kretprobe(&kretprobe[i]);
		printk(KERN_INFO "kretprobe at %p unregistered\n",
				kretprobe[i].kp.addr);
	}
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
