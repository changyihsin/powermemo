/* kprobe_example.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

/*For each probe you need to allocate a kprobe structure*/
static struct kprobe kp[1000];
static struct kprobe *pkp = NULL;

static int start_addr = 0;       /* Added driver parameter */
module_param(start_addr, int, 0);  /* and these 2 lines */

static int end_addr = 0;       /* Added driver parameter */
module_param(end_addr, int, 0);  /* and these 2 lines */

static char app_name[NAME_MAX] = "";
module_param_string(app, app_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(app, "application to do uretprobe; this module will report the"
            " all functions's execution time within this application");

int total_calls = 0;

/*kprobe pre_handler: called just before the probed instruction is executed*/
int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	printk("\nkprobes => pre_handler\n");
	total_calls++;
	//dump_stack();
	/* It must return 0 in normal case */
	return 0;
}

/*kprobe post_handler: called after the probed instruction is executed*/
void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	printk("\nkprobes => post_handler\n");
}

/* fault_handler: this is called if an exception is generated for any
 *  * instruction within the pre- or post-handler, or when Kprobes
 *   * single-steps the probed instruction.
 *    */
int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk("kprobes => fault_handler\n");
	/* Return 0 because we don't handle the fault. */
	return 0;
}

int index = 0;
static int __init init_kprobe_test(void)
{
	int ret;
	int addr;
	
	for ((index = 0, addr = start_addr); (addr <= end_addr && index < 1000); (index++, addr += 4))
    {
        printk("index=%d addr=0x%x\n", index, addr);
        pkp = &kp[index];
        if (pkp == NULL)
        {
            printk("kmalloc error %d\n", addr);
            return -1;
        }
		pkp->pre_handler = handler_pre;
		//pkp->post_handler = handler_post;
		//pkp->fault_handler = handler_fault;
        pkp->addr = addr;
        /* register the kprobe now */
        if (!pkp->addr) {
            printk("Couldn't find probe to plant kprobe\n");
            return -1;
        }
        if ((ret = register_kprobe(pkp) < 0)) {
            printk("register_kprobe failed, returned %d\n", ret);
            return -1;
		}
		printk("kprobe registered %d\n", index);

	}
	return 0;
}

static void __exit exit_kprobe_test(void)
{
	int i = 0;

    for (i = 0; i < index; i++)
    {
        unregister_kprobe(&kp[i]);
    }
	printk("kprobe unregistered Total Calls=%d\n", total_calls);
	total_calls = 0;
}

module_init(init_kprobe_test);
module_exit(exit_kprobe_test);

MODULE_LICENSE("GPL");
