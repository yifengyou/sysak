#include <linux/module.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>			/* regs_get_kernel_argument */
#include <linux/threads.h>		/* PID_MAX_LIMIT */
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/tracepoint.h>
#include <linux/stacktrace.h>
#include "sysak_mods.h"
#include "common/proc.h"

/* ARRAY_LEN is to define a trace buffer */
#define ARRAY_LEN	1
#define BUF_LEN		1024	
#define MAX_STACK_TRACE_DEPTH 8

struct tracepoints_probe {
	struct tracepoint *tp;
	char *name;
};

struct traceinfo {
	int idx;
	struct stack_trace trace[ARRAY_LEN];
	unsigned long entries[ARRAY_LEN][MAX_STACK_TRACE_DEPTH];
};

static int trace_in_fly;
static int target_pid;
char buff[BUF_LEN] = {0};
struct traceinfo traceinfos;

struct tracepoints_probe mytp = {
	.tp = NULL,
	.name = "sched_switch",
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static struct tracepoint **swtc__start___tracepoints_ptrs;
static struct tracepoint **swtc__stop___tracepoints_ptrs;

static int swtc_init_local_tracepoints(void)
{
	swtc__start___tracepoints_ptrs = (void *)kallsyms_lookup_name("__start___tracepoints_ptrs");
	swtc__stop___tracepoints_ptrs  = (void *)kallsyms_lookup_name("__stop___tracepoints_ptrs");
	if (swtc__start___tracepoints_ptrs == NULL || swtc__stop___tracepoints_ptrs == NULL) {
		return -1;
	}
	return 0;
}

static void swtc_for_each_tracepoint_range(struct tracepoint * const *begin,
		struct tracepoint * const *end,
		void (*fct)(struct tracepoint *tp, void *priv),
		void *priv)
{
	struct tracepoint * const *iter;

	if (!begin)
		return;
	for (iter = begin; iter < end; iter++)
		fct(*iter, priv);
}

/**
 * for_each_kernel_tracepoint - iteration on all kernel tracepoints
 * @fct: callback
 * @priv: private data
 */
void swtc_for_each_kernel_tracepoint(void (*fct)(struct tracepoint *tp, void *priv),
		void *priv)
{
	swtc_for_each_tracepoint_range(swtc__start___tracepoints_ptrs,
		swtc__stop___tracepoints_ptrs, fct, priv);
}
#endif
static void tracepoint_lookup(struct tracepoint *tp, void *priv)
{
	struct tracepoints_probe *tps = priv;

	if (!strcmp(tp->name, tps->name))
		tps->tp = tp;
}

static void
(*stack_save_regs)(struct pt_regs *regs, struct stack_trace *trace);
static void
(*stack_save_tsk)(struct task_struct *tsk, struct stack_trace *trace);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static void trace_sched_switch(void *priv,
			       struct task_struct *prev,
			       struct task_struct *next)

#else
static void trace_sched_switch(void *priv, bool preempt,
			       struct task_struct *prev,
			       struct task_struct *next)
#endif
{
	struct task_struct *p;
	int i, size = 0;

	p = prev;
	if (((pid_t)target_pid == p->pid) && (p->state)) {
		struct traceinfo *tf = &traceinfos;
		struct stack_trace *trace = tf->trace;
		int idx = tf->idx;

		tf->idx = (idx + 1)%ARRAY_LEN;
		trace->nr_entries = 0;
		trace->entries = tf->entries[idx];
		trace->max_entries = MAX_STACK_TRACE_DEPTH;
		trace->skip = 1;
		stack_save_tsk(prev, trace);

		idx = 0;
		for (i = 0; i < trace->nr_entries - 1; i++) {
			if ((void *)trace->entries[i]) {
				size = sprintf(&buff[idx], "<%px>", (void *)(trace->entries[i]));
				idx += size;
				if (idx > BUF_LEN)
					break;
				size = sprint_symbol(&buff[idx], trace->entries[i]);
				idx += size;
				if (idx > BUF_LEN)
					break;
				size = sprintf(&buff[idx], ",");
				idx += size;
				if (idx > BUF_LEN)
					break;
			}
		}
		trace_printk("%s\n", buff);
		memset(trace, 0, sizeof(struct stack_trace));
	}
}

static int pid_show(struct seq_file *m, void *v)
{
	seq_printf(m, "pid=%d\n", target_pid);
	return 0;
}

static int pid_open(struct inode *inode, struct file *file)
{
	return single_open(file, pid_show, inode->i_private);
}

static ssize_t pid_write(struct file *f, const char __user *buf,
			size_t count, loff_t *ppos)
{
	if (count <= 0 || count > PID_MAX_LIMIT)
		return -EINVAL;

	if (kstrtoint_from_user(buf, count, 0, &target_pid)) {
		pr_warn("copy_from_user fail\n");
		return -EFAULT;
	}

	if (target_pid < 0 && target_pid != -1)
		return -EINVAL;

	if (target_pid == -1 && trace_in_fly) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		tracepoint_probe_unregister(mytp.name, trace_sched_switch, NULL);	
#else
		tracepoint_probe_unregister(mytp.tp, trace_sched_switch, NULL);	
#endif
		trace_in_fly = 0;
	} else if (target_pid > 0 && !trace_in_fly) {
		int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		ret = tracepoint_probe_register(mytp.name, trace_sched_switch, NULL);	
#else
		ret = tracepoint_probe_register(mytp.tp, trace_sched_switch, NULL);
#endif
		if (ret)
			trace_in_fly = 1;
		else
			return ret;
	}
	return count;
}

static struct file_operations pid_fops = {
	.owner		=	THIS_MODULE,
	.read		=	seq_read,
	.open		=	pid_open,
	.write		=	pid_write,
	.release	=	seq_release,
};

static int proc_init(void)
{
	struct proc_dir_entry *parent;

	parent = sysak_proc_mkdir("schedtrace");
	if (!parent)
		return -ENOMEM;

	if(!proc_create("pid", 
			S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP,
			parent,
			&pid_fops))
		goto proc_fail;
	pr_info("proc_init schedtrace success\n");
	return 0;

proc_fail:
	sysak_remove_proc_entry("schedtrace");
	return -ENOMEM;
}

int schedtrace_init(void)
{
	int ret;

	mytp.tp = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	if (swtc_init_local_tracepoints())
		return -ENODEV;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	swtc_for_each_kernel_tracepoint(tracepoint_lookup, &mytp);
#else
	for_each_kernel_tracepoint(tracepoint_lookup, &mytp);
#endif
	if (mytp.tp) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		ret = tracepoint_probe_register(mytp.name, trace_sched_switch, NULL);	
#else
		ret = tracepoint_probe_register(mytp.tp, trace_sched_switch, NULL);
#endif
		if (ret) {
			pr_warn("sched_switch probe fail\n");
			return ret;
		}
		trace_in_fly = 1;
	}

	stack_save_tsk = (void *)kallsyms_lookup_name("save_stack_trace_tsk");
	stack_save_regs = (void *)kallsyms_lookup_name("save_stack_trace_regs");

	if (!stack_save_tsk || !stack_save_regs) {
		ret = -EINVAL;
		goto fail;
	}

	ret = proc_init();
	if (ret < 0) {
		pr_warn("proc_init fail\n");
		goto fail;
	}

	target_pid = -1;
	return ret;
fail:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	tracepoint_probe_unregister(mytp.name, trace_sched_switch, NULL);
#else
	tracepoint_probe_unregister(mytp.tp, trace_sched_switch, NULL);
#endif
	return ret;
}

void schedtrace_exit(void)
{
	if (trace_in_fly)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		tracepoint_probe_unregister(mytp.name, trace_sched_switch, NULL);
#else
		tracepoint_probe_unregister(mytp.tp, trace_sched_switch, NULL);
#endif
}
