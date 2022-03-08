// SPDX-License-Identifier: GPL-2.0
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/cpuset.h>
#include <linux/kallsyms.h>

#include "common/proc.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static void *orig_tasklist_lock;
void (*orig_get_avenrun)(unsigned long *loads, unsigned long offset, int shift);
#ifdef CONFIG_RICH_CONTAINER
int *orig_sysctl_rich_container_enable;
bool (*orig_child_cpuacct)(struct task_struct *tsk);
static void (*orig_get_avenrun_r)(unsigned long *loads, unsigned long offset,
	int shift);
static void (*orig_get_cgroup_avenrun)(struct task_struct *tsk,
		unsigned long *loads, unsigned long offset,
		int shift, bool running);
static inline bool orig_in_rich_container(struct task_struct *tsk)
{
	if (*orig_sysctl_rich_container_enable == 0)
		return false;

	return (task_active_pid_ns(tsk) != &init_pid_ns) && orig_child_cpuacct(tsk);
}
#else
static inline void (*orig_get_avenrun_r)(unsigned long *loads, unsigned long offset,
	int shift) { }
static inline void (*orig_get_cgroup_avenrun)(struct task_struct *tsk,
		unsigned long *loads, unsigned long offset,
		int shift, bool running) { }
static inline bool orig_in_rich_container(struct task_struct *tsk)
{
	return false;
}
#endif
#endif

static int loadtask_show(struct seq_file *m, void *v)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	unsigned long avnrun[3], avnrun_r[3];

	rcu_read_lock();
	if (orig_in_rich_container(current)) {
		struct task_struct *init_tsk;

		read_lock(orig_tasklist_lock);
		init_tsk = task_active_pid_ns(current)->child_reaper;
		get_task_struct(init_tsk);
		read_unlock(orig_tasklist_lock);
		orig_get_cgroup_avenrun(init_tsk, avnrun, FIXED_1/200, 0, false);
        orig_get_cgroup_avenrun(init_tsk, avnrun_r, FIXED_1/200, 0, true);
		put_task_struct(init_tsk);
	} else {
		orig_get_avenrun(avnrun, FIXED_1/200, 0);
        orig_get_avenrun_r(avnrun_r, FIXED_1/200, 0);
	}
	rcu_read_unlock();

	seq_printf(m, "loadavg: %lu.%02lu %lu.%02lu %lu.%02lu\n",
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]));
    seq_printf(m, "loadavg_r: %lu.%02lu %lu.%02lu %lu.%02lu\n",
		LOAD_INT(avnrun_r[0]), LOAD_FRAC(avnrun_r[0]),
		LOAD_INT(avnrun_r[1]), LOAD_FRAC(avnrun_r[1]),
		LOAD_INT(avnrun_r[2]), LOAD_FRAC(avnrun_r[2]));
    seq_printf(m, "loadavg_d: %lu.%02lu %lu.%02lu %lu.%02lu\n",
		LOAD_INT(avnrun[0] - avnrun_r[0]), LOAD_FRAC(avnrun[0] - avnrun_r[0]),
		LOAD_INT(avnrun[1] - avnrun_r[1]), LOAD_FRAC(avnrun[1] - avnrun_r[1]),
		LOAD_INT(avnrun[2] - avnrun_r[2]), LOAD_FRAC(avnrun[2] - avnrun_r[2]));
#endif
	return 0;
}

DEFINE_PROC_ATTRIBUTE_RO(loadtask);

int loadtask_init(void)
{
	struct proc_dir_entry *parent_dir;
	struct proc_dir_entry *entry_print;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
    orig_tasklist_lock = (void *)kallsyms_lookup_name("tasklist_lock");
	if (!orig_tasklist_lock)
		return -1;
    orig_get_avenrun = (void *)kallsyms_lookup_name("get_avenrun");
	if (!orig_get_avenrun)
		return -1;
#ifdef CONFIG_RICH_CONTAINER
    orig_get_avenrun_r = (void *)kallsyms_lookup_name("get_avenrun_r");
	if (!orig_get_avenrun_r)
		return -1;
    orig_get_cgroup_avenrun = (void *)kallsyms_lookup_name("get_cgroup_avenrun");
	if (!orig_get_cgroup_avenrun)
		return -1;
    orig_sysctl_rich_container_enable= (void *)kallsyms_lookup_name("sysctl_rich_container_enable");
	if (!orig_sysctl_rich_container_enable)
		return -1;
#endif   
    orig_child_cpuacct = (void *)kallsyms_lookup_name("child_cpuacct");
	if (!orig_child_cpuacct)
		return -1;
#endif
	parent_dir = sysak_proc_mkdir("loadtask");
	if (!parent_dir) {
		goto failed_root;
	}

	entry_print = proc_create("loadavg", 0444, parent_dir, &loadtask_fops);
    	if(!entry_print)
    		goto failed;
	return 0;

failed:
	sysak_remove_proc_entry("loadtask");
failed_root:
	return -1;
}

int loadtask_exit(void)
{
    return 0;
}