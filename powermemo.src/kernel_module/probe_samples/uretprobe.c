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
#include <linux/moduleparam.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>

static char func_name[NAME_MAX] = "do_fork";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
			" function's execution time");


#define MAX_FUNCS 500

static int addr = 0;       /* Added driver parameter */
module_param(addr, int, 0);  /* and these 2 lines */


static int multi_addr[MAX_FUNCS];
static int multi_addr_num = 0;
module_param_array(multi_addr, int, &multi_addr_num, 0000);

static char app_name[NAME_MAX] = "";
module_param_string(app, app_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(app, "application to do uretprobe; this module will report the"
			" all functions's execution time within this application");


static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

static struct kretprobe retprobe[MAX_FUNCS];

/* per-instance private data */
struct my_data {
	ktime_t entry_stamp;
};

int function_calls = 0;
/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct my_data *)ri->data;
	data->entry_stamp = ktime_get();
	function_calls++;
	//printk("entry:%d\n", function_calls);
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
	//printk(KERN_INFO "exe_time %lld ns addr:%x calls:%d\n", (long long)delta, ri->rp->up.kp.addr, function_calls);
	return 0;
}

char path_name[64];
static int __init kretprobe_init(void)
{
	int ret, i;	
	struct nameidata nd;
	char *path_prefix[] = {"/data/powermemo/", "/system/bin/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/data/powermemo/lmbench/bin/"};
	int tpath = sizeof(path_prefix)/sizeof(char *);

	for (i = 0; i < tpath; i++) {
		sprintf(path_name, "%s%s", path_prefix[i], app_name);
		if ((ret = path_lookup(path_name, LOOKUP_FOLLOW, &nd)) == 0) break; 				
	}
	
	if (ret != 0){
		printk("Invalid image name %s, path lookup fail\n", path_name);
		return -1;
	}

	for (i = 0; i < multi_addr_num; i++)
	{
		printk("addr=0x%x maxaddr=%d app_name=%s\n", multi_addr[i], multi_addr_num, app_name);
		retprobe[i].handler = ret_handler;
		retprobe[i].entry_handler = entry_handler;
		retprobe[i].data_size = sizeof(struct my_data);
		retprobe[i].maxactive = 20;
		retprobe[i].up.pathname = path_name;
		retprobe[i].up.kp.addr = multi_addr[i];
		retprobe[i].up.offset = multi_addr[i]-0x8000;
		printk("i = %d addr = 0x%x offset = 0x%x\n", i, retprobe[i].up.kp.addr, retprobe[i].up.offset);
		ret = register_uretprobe(&retprobe[i]);
		if (ret < 0) {
			printk(KERN_INFO "register_kretprobe failed, returned %d\n",
					ret);
			return -1;
		}		
		printk(KERN_INFO "Planted return probe at: %p\n", retprobe[i].up.kp.addr);
	}	
	return 0;
}

static void __exit kretprobe_exit(void)
{
	int i = 0; 

	for (i = 0; i < multi_addr_num; i++)
	{
		unregister_uretprobe(&retprobe[i]);
		printk(KERN_INFO "kretprobe at %p unregistered\n", retprobe[i].up.kp.addr);
	}
	printk("number of function calls = %d\n", function_calls);
	function_calls = 0;
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
