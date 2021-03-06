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
#include "sysak_mods.h"

static int sysak_mod_init(void)
{
	int i;

	sysak_dev_init();

	for (i = 0; i < sysk_module_num; i++) {
		if (sysak_modules[i].init())
			printk("WARN: module %s init failed", sysak_modules[i].name);
	}

	printk("sysak module loaded.\n");
	return 0;
}

static void sysak_mod_exit(void)
{
	int i;

	sysak_dev_uninit();

	for (i = 0; i < sysk_module_num; i++)
		sysak_modules[i].exit();

	printk("sysak module unloaded.\n");
}

module_init(sysak_mod_init)
module_exit(sysak_mod_exit)
MODULE_LICENSE("GPL v2");
