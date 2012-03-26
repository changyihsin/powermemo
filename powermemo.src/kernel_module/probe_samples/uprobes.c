/* kprobe_example.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/sched.h>

/*For each probe you need to allocate a uprobe structure*/
static struct uprobe p1;
static struct uprobe p2;
static struct uprobe p3;
static struct uprobe p4;
static struct uprobe p5;
static struct uprobe p6;
static struct uprobe p7;
static struct uprobe p8;
static struct uprobe p9;
static struct uprobe p10;
static struct uprobe p[1000];
static struct uprobe *pp = NULL;
static int start_addr = 0;       /* Added driver parameter */
module_param(start_addr, int, 0);  /* and these 2 lines */

static int end_addr = 0;       /* Added driver parameter */
module_param(end_addr, int, 0);  /* and these 2 lines */

static char app_name[NAME_MAX] = "";
module_param_string(app, app_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(app, "application to do uretprobe; this module will report the"
			" all functions's execution time within this application");


int total_calls = 0;
int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	total_calls++;//printk("p(%x) => pre_handler, addr=0x%x\n", (unsigned int)p, p->addr);
	printk("handler_pre uprobes\n");
	return 0;
}

int handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	printk("p(%x) => post_handler\n", (unsigned int)p);
	return 0;
}

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk("p(%x) => fault_handler\n", (unsigned int)p);
	return 0;
}

int index = 0;
char path_name[64];
static int __init init_uprobe_test(void)
{
	int ret, i;	
	struct nameidata nd;
	int addr = 0;
	char *path_prefix[] = {"/data/powermemo/", "/data/powermemo/lmbench/bin/", "/system/bin/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lmbenchmark/bin/"};
	int tpath = sizeof(path_prefix)/sizeof(char *);
	

	for (i = 0; i < tpath; i++) {
		sprintf(path_name, "%s%s", path_prefix[i], app_name);
		if ((ret = path_lookup(path_name, LOOKUP_FOLLOW, &nd)) == 0) break; 				
	}
	
	if (ret != 0){
		printk("Invalid image name %s, path lookup fail\n", path_name);
		return -1;
	}
	printk("uprobes start_addr=0x%x end_addr=0x%x\n", start_addr, end_addr);
	for ((index = 0, addr = start_addr); (addr <= end_addr && index < 1000); (index++, addr += 4))
	{
		printk("index=%d addr=0x%x\n", index, addr);
		pp = &p[index];
		if (pp == NULL)
		{
			printk("kmalloc error %d\n", addr);
			return -1;
		}
		pp->pathname = path_name;
		pp->kp.pre_handler = handler_pre;
		pp->kp.post_handler = NULL;
		pp->kp.fault_handler = NULL;
		pp->kp.addr = addr;
		pp->offset = addr-0x8000;//(unsigned long)(pp->kp.addr);
		/* register the kprobe now */
		if (!pp->kp.addr) {
			printk("Couldn't find kprobe\n");
			return -1;
		}
		printk("addr = %x offset = %x index = %d start=%x end=%x\n", pp->kp.addr, pp->offset, index, start_addr, end_addr);
		if ((ret = register_uprobe(pp) < 0)) {
			printk("register_uprobe failed, returned %d\n", ret);
			return -1;
		}
	}
	#if 0
	p1.pathname = "/bin/uprobe_test";
	p1.kp.pre_handler = handler_pre;
	p1.kp.post_handler = handler_post;
	p1.kp.fault_handler = handler_fault;
	p1.kp.addr = 0x000084e8;
	p1.offset = (unsigned long)p1.kp.addr&0xfff;
	/* register the kprobe now */
	if (!p1.kp.addr) {
		printk("Couldn't find kprobe\n");
		return -1;
	}
	if ((ret = register_uprobe(&p1) < 0)) {
		printk("register_uprobe failed, returned %d\n", ret);
		return -1;
	}
	
    p2.pathname = "/bin/uprobe_test";
    p2.kp.pre_handler = handler_pre;
    p2.kp.post_handler = handler_post;
    p2.kp.fault_handler = handler_fault;
    p2.kp.addr = 0x0000854c;
    p2.offset = (unsigned long)0x0000054c;
    /* register the kprobe now */
    if (!p2.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p2) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }
	
    p3.pathname = "/bin/uprobe_test";
    p3.kp.pre_handler = handler_pre;
    p3.kp.post_handler = handler_post;
    p3.kp.fault_handler = handler_fault;
    p3.kp.addr = 0x0000855c;
    p3.offset = (unsigned long)0x0000055c;
    /* register the kprobe now */
    if (!p3.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p3) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }
	
    p4.pathname = "/bin/uprobe_test";
    p4.kp.pre_handler = handler_pre;
    p4.kp.post_handler = handler_post;
    p4.kp.fault_handler = handler_fault;
    p4.kp.addr = 0x000085f4;
    p4.offset = (unsigned long)0x000005f4;
    /* register the kprobe now */
    if (!p4.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p4) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }

    p5.pathname = "/bin/uprobe_test";
    p5.kp.pre_handler = handler_pre;
    p5.kp.post_handler = handler_post;
    p5.kp.fault_handler = handler_fault;
    p5.kp.addr = 0x00008604;
    p5.offset = (unsigned long)0x00000604;
    /* register the kprobe now */
    if (!p5.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p5) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }

    p6.pathname = "/bin/uprobe_test";
    p6.kp.pre_handler = handler_pre;
    p6.kp.post_handler = handler_post;
    p6.kp.fault_handler = handler_fault;
    p6.kp.addr = 0x00008618;
    p6.offset = (unsigned long)0x00000618;
    /* register the kprobe now */
    if (!p6.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p6) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }
    p7.pathname = "/bin/uprobe_test";
    p7.kp.pre_handler = handler_pre;
    p7.kp.post_handler = handler_post;
    p7.kp.fault_handler = handler_fault;
    p7.kp.addr = 0x00008620;
    p7.offset = (unsigned long)0x00000620;
    /* register the kprobe now */
    if (!p7.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p7) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }
    p8.pathname = "/bin/uprobe_test";
    p8.kp.pre_handler = handler_pre;
    p8.kp.post_handler = handler_post;
    p8.kp.fault_handler = handler_fault;
    p8.kp.addr = 0x00008634;
    p8.offset = (unsigned long)0x00000634;
    /* register the kprobe now */
    if (!p8.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p8) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }
    p9.pathname = "/bin/uprobe_test";
    p9.kp.pre_handler = handler_pre;
    p9.kp.post_handler = handler_post;
    p9.kp.fault_handler = handler_fault;
    p9.kp.addr = 0x0000863c;
    p9.offset = (unsigned long)0x0000063c;
    /* register the kprobe now */
    if (!p9.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p9) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }
    p10.pathname = "/bin/uprobe_test";
    p10.kp.pre_handler = handler_pre;
    p10.kp.post_handler = handler_post;
    p10.kp.fault_handler = handler_fault;
    p10.kp.addr = 0x00008650;
    p10.offset = (unsigned long)0x00000650;
    /* register the kprobe now */
    if (!p10.kp.addr) {
        printk("Couldn't find kprobe\n");
        return -1;
    }
    if ((ret = register_uprobe(&p10) < 0)) {
        printk("register_uprobe failed, returned %d\n", ret);
        return -1;
    }

	#endif
	printk("uprobe registered\n");
	return 0;
}

static void __exit exit_uprobe_test(void)
{
	int i = 0;

	for (i = 0; i < index; i++)
	{
		unregister_uprobe(&p[i]);
	}
	#if 0
	unregister_uprobe(&p1);
	unregister_uprobe(&p2);
	unregister_uprobe(&p3);
	unregister_uprobe(&p4);
	unregister_uprobe(&p5);
	unregister_uprobe(&p6);
	unregister_uprobe(&p7);
	unregister_uprobe(&p8);
	unregister_uprobe(&p9);
	unregister_uprobe(&p10);
	#endif
	printk("uprobe unregistered Total Calls=%d\n", total_calls);
	total_calls = 0;
}

module_init(init_uprobe_test);
module_exit(exit_uprobe_test);

MODULE_LICENSE("GPL");
