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
#include "common/hook.h"
#include "common/proc.h"

enum TASK_CTL_TYPE{
	TASK_LOOP,
	TASK_SLEEP,
	MAX_CTL_TYPE	
};

#define TASK_CTL_VALID(x) ((unsigned)(x) < MAX_CTL_TYPE)

struct task_ctl_info {
	int pid;
	enum TASK_CTL_TYPE type;
}ctl_info;

static int taskctl_ref;
static bool ctl_enabled;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void syscall_enter_trace(struct pt_regs *regs, long id)
#else
static void syscall_enter_trace(void *__data, struct pt_regs *regs, long id)
#endif
{
	while(ctl_enabled && ctl_info.pid == current->pid) {
		if (!TASK_CTL_VALID(ctl_info.type))
			break;
		else if (ctl_info.type == TASK_SLEEP)
			msleep_interruptible(100);
		else
			cond_resched();
		rmb();
	}
}

static void task_ctl_enable(void)
{
	if (ctl_enabled)
		return;
	hook_tracepoint("sys_enter", syscall_enter_trace, NULL);
	ctl_enabled = true;
	sysak_module_get(&taskctl_ref);
}

static void task_ctl_disable(void)
{
	if (!ctl_enabled)
		return;

	unhook_tracepoint("sys_enter", syscall_enter_trace, NULL);
	synchronize_sched();
	ctl_enabled = false;
	sysak_module_put(&taskctl_ref);
}

static ssize_t task_ctl_write(struct file *file,
		const char __user *buf, size_t count, loff_t *offs)
{
	int ret;
	char cmd[256];
	char chr[256];
	int pid;

	if (count < 1 || *offs)
		return -EINVAL;

	if (copy_from_user(chr, buf, 256))
		return -EFAULT;

	ret = sscanf(chr, "%255s", cmd);
	if (ret <= 0)
		return -EINVAL;

	if (strcmp(cmd, "pid") == 0) {
		ret = sscanf(chr, "pid %d", &pid);
		if (ret <= 0)
			return -EINVAL;
		ctl_info.pid = pid;
	} else if (strcmp(cmd, "type") == 0) {
		ret = sscanf(chr, "type %s", cmd);
		if (ret <= 0)
			return -EINVAL;
		if (strcmp(cmd, "loop") == 0)
			ctl_info.type = TASK_LOOP;
		else if (strcmp(cmd, "sleep") == 0)
			ctl_info.type = TASK_SLEEP;
		else
			ctl_info.type = MAX_CTL_TYPE;
	} else if (strcmp(cmd, "enable") == 0) {
		task_ctl_enable();
	} else if (strcmp(cmd, "disable") == 0) {
                task_ctl_disable();
        } else {
		return -EINVAL;
	}

	return count;
}

static int task_ctl_show(struct seq_file *m, void *v)
{
	seq_printf(m, "pid: %d\n", ctl_info.pid);
	if (ctl_info.type == TASK_LOOP)
		seq_printf(m, "type: loop");
	else if (ctl_info.type == TASK_SLEEP)
		seq_printf(m, "type: sleep");
	else
		seq_printf(m, "type: invalid");

	return 0;
}

static int task_ctl_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, task_ctl_show, NULL);
}

static struct proc_dir_entry *task_ctl_proc;
const struct file_operations task_ctl_fops = {
	.open = task_ctl_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = task_ctl_write,
	.release = single_release,
};

int task_ctl_init(void)
{
	task_ctl_proc = sysak_proc_create("task_ctl", &task_ctl_fops);
	
	return 0;
}

int task_ctl_exit(void)
{
	task_ctl_disable();
	return 0;
}

