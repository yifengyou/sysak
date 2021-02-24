#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/tracepoint.h>
#include <linux/cgroup.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/kthread.h>

int test_init(void)
{
	printk("test_module enter.\n");
	return 0;
}

int test_exit(void)
{
	printk("test_module exit.\n");
	return 0;
}

