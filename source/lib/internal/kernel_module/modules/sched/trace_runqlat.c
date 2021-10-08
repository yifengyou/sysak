#define pr_fmt(fmt) "runqlat: " fmt

#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/timer.h>
#include <linux/tracepoint.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <trace/events/sched.h>
#include "sysak_mods.h"
#include "common/proc.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#include <linux/sched.h>
#else
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#endif

#define MAX_TRACE_ENTRIES		128
#define PER_TRACE_ENTRY_TASKS		16
#define MAX_TRACE_ENTRY_TASKS		\
	(MAX_TRACE_ENTRIES * PER_TRACE_ENTRY_TASKS)

#define THRESHOLD_DEFAULT		(20 * 1000 * 1000UL)

#define INVALID_PID			-1
#define INVALID_CPU			-1
#define PROBE_TRACEPOINTS		 4

/**
 * If we call register_trace_sched_{wakeup,wakeup_new,switch,migrate_task}()
 * directly in a kernel module, the compiler will complain about undefined
 * symbol of __tracepoint_sched_{wakeup, wakeup_new, switch, migrate_task}
 * because the kernel do not export the tracepoint symbol. Here is a workaround
 * via for_each_kernel_tracepoint() to lookup the tracepoint and save.
 */
struct tracepoints_probe {
	struct tracepoint *tps[PROBE_TRACEPOINTS];
	const char *tp_names[PROBE_TRACEPOINTS];
	void *tp_probes[PROBE_TRACEPOINTS];
	void *priv;
	int num_initalized;
};

struct task_entry {
	u64 runtime;
	pid_t pid;
	char comm[TASK_COMM_LEN];
};

struct trace_entry {
	u64 latency;
	u64 rq_start;
	unsigned int nr_tasks;
	struct task_entry *entries;
};

struct runqlat_info {
	int cpu;		/* The target CPU */
	pid_t pid;		/* Trace this pid only */
	u64 rq_start;
	u64 run_start;
	u64 threshold;
	struct task_struct *curr;

	unsigned int nr_trace;
	struct trace_entry *trace_entries;

	unsigned int nr_task;
	struct task_entry *task_entries;

	arch_spinlock_t lock;
};

static struct runqlat_info runqlat_info = {
	.pid		= INVALID_PID,
	.cpu		= INVALID_CPU,
	.threshold	= THRESHOLD_DEFAULT,
	.lock		= __ARCH_SPIN_LOCK_UNLOCKED,
};

static int runqlat_ref;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static struct tracepoint **runq__start___tracepoints_ptrs;
static struct tracepoint **runq__stop___tracepoints_ptrs;

static int runq_init_local_tracepoints(void)
{
	runq__start___tracepoints_ptrs = (void *)kallsyms_lookup_name("__start___tracepoints_ptrs");
	runq__stop___tracepoints_ptrs  = (void *)kallsyms_lookup_name("__stop___tracepoints_ptrs");
	if (runq__start___tracepoints_ptrs == NULL || runq__stop___tracepoints_ptrs == NULL) {
		return -1;
	}
	return 0;
}

static void runq_for_each_tracepoint_range(struct tracepoint * const *begin,
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
void runq_for_each_kernel_tracepoint(void (*fct)(struct tracepoint *tp, void *priv),
		void *priv)
{
	runq_for_each_tracepoint_range(runq__start___tracepoints_ptrs,
		runq__stop___tracepoints_ptrs, fct, priv);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static void probe_sched_wakeup(void *priv, struct task_struct *p, int success)
#else
static void probe_sched_wakeup(void *priv, struct task_struct *p)
#endif
{
	struct runqlat_info *info = priv;

	if (p->pid != info->pid)
		return;

	/* interrupts should be off from try_to_wake_up() */
	arch_spin_lock(&info->lock);
	if (unlikely(p->pid != info->pid)) {
		arch_spin_unlock(&info->lock);
		return;
	}

	info->rq_start = local_clock();
	info->run_start = info->rq_start;
	info->cpu = task_cpu(p);
	arch_spin_unlock(&info->lock);
}

static inline void runqlat_info_reset(struct runqlat_info *info)
{
	info->rq_start = 0;
	info->run_start = 0;
	info->cpu = INVALID_CPU;
	info->curr = NULL;
}

/* Must be called with @info->lock held */
static void record_task(struct runqlat_info *info, struct task_struct *p,
			u64 runtime)
	__must_hold(&info->lock)
{
	struct task_entry *task;
	struct trace_entry *trace;

	task = info->task_entries + info->nr_task;
	trace = info->trace_entries + info->nr_trace;

	if (trace->nr_tasks == 0)
		trace->entries = task;
	WARN_ON_ONCE(trace->entries != task - trace->nr_tasks);
	trace->nr_tasks++;

	task->pid = p->pid;
	task->runtime = runtime;
	strncpy(task->comm, p->comm, TASK_COMM_LEN);

	info->nr_task++;
	if (unlikely(info->nr_task >= MAX_TRACE_ENTRY_TASKS)) {
		pr_info("BUG: MAX_TRACE_ENTRY_TASKS too low!");
		runqlat_info_reset(info);
		/* Force disable trace */
		info->pid = INVALID_PID;
	}
}

/* Must be called with @info->lock held */
static bool record_task_commit(struct runqlat_info *info, u64 latency)
	__must_hold(&info->lock)
{
	struct trace_entry *trace;

	trace = info->trace_entries + info->nr_trace;
	if (trace->nr_tasks == 0)
		return false;

	if (latency >= info->threshold) {
		trace->latency = latency;
		trace->rq_start = info->rq_start;
		info->nr_trace++;
		if (unlikely(info->nr_trace >= MAX_TRACE_ENTRIES)) {
			pr_info("BUG: MAX_TRACE_ENTRIES too low!");
			runqlat_info_reset(info);
			/* Force disable trace */
			info->pid = INVALID_PID;
		}
	} else {
		info->nr_task -= trace->nr_tasks;
		trace->nr_tasks = 0;
		trace->entries = NULL;
	}

	return true;
}

/* interrupts should be off from __schedule() */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static void probe_sched_switch(void *priv,
			       struct task_struct *prev,
			       struct task_struct *next)
#else
static void probe_sched_switch(void *priv, bool preempt,
			       struct task_struct *prev,
			       struct task_struct *next)
#endif
{
	struct runqlat_info *info = priv;
	int cpu = smp_processor_id();
	arch_spinlock_t *lock = &info->lock;

	if (info->pid == INVALID_PID)
		return;

	if (info->cpu != INVALID_CPU && info->cpu != cpu)
		return;

	if (READ_ONCE(info->cpu) == INVALID_CPU) {
		if (READ_ONCE(info->pid) != prev->pid ||
		    prev->state != TASK_RUNNING)
			return;

		arch_spin_lock(lock);
		/* We could race with grabbing lock */
		if (unlikely(info->cpu != INVALID_CPU ||
			     info->pid != prev->pid)) {
			arch_spin_unlock(lock);
			return;
		}
		info->rq_start = cpu_clock(cpu);
		info->run_start = info->rq_start;
		info->cpu = task_cpu(prev);

		/* update curr for migrate task probe using*/
		if (!is_idle_task(next))
			info->curr = next;
		arch_spin_unlock(lock);
	} else {
		u64 now;

		if (unlikely(READ_ONCE(info->cpu) != cpu ||
			     READ_ONCE(info->pid) == INVALID_PID))
			return;

		arch_spin_lock(lock);
		/* We could race with grabbing lock */
		if (unlikely(info->cpu != cpu || info->pid == INVALID_PID)) {
			arch_spin_unlock(lock);
			return;
		}

		/* update curr for migrate task probe using*/
		if (!is_idle_task(next))
			info->curr = next;

		now = cpu_clock(cpu);
		if (info->pid == next->pid) {
			if (info->run_start)
				record_task(info, prev, now - info->run_start);
			record_task_commit(info, now - info->rq_start);
		} else if (info->pid == prev->pid) {
			if (prev->state == TASK_RUNNING) {
				info->rq_start = now;
				info->run_start = now;
			} else {
				runqlat_info_reset(info);
			}
		} else {
			if (info->run_start)
				record_task(info, prev, now - info->run_start);
			info->run_start = now;
		}
		arch_spin_unlock(lock);
	}
}

static void probe_sched_migrate_task(void *priv, struct task_struct *p, int cpu)
{
	u64 now;
	struct runqlat_info *info = priv;
	struct task_struct *curr;

	if (p->pid != info->pid || info->cpu == INVALID_CPU)
		return;

	/* interrupts should be off from set_task_cpu() */
	arch_spin_lock(&info->lock);
	if (unlikely(p->pid != info->pid || info->cpu == INVALID_CPU))
		goto unlock;

	now = local_clock();
	curr = info->curr;
	if (curr) {
		get_task_struct(curr);
		if (info->run_start)
			record_task(info, curr, now - info->run_start);
		put_task_struct(curr);
	}

	info->cpu = cpu;
	info->run_start = now;
unlock:
	arch_spin_unlock(&info->lock);
}

static struct tracepoints_probe tps_probe = {
	.tp_names = {
		"sched_wakeup",
		"sched_wakeup_new",
		"sched_switch",
		"sched_migrate_task",
	},
	.tp_probes = {
		probe_sched_wakeup,
		probe_sched_wakeup,
		probe_sched_switch,
		probe_sched_migrate_task,
	},
	.priv = &runqlat_info,
};

static inline bool is_tracepoint_lookup_success(struct tracepoints_probe *tps)
{
	return tps->num_initalized == PROBE_TRACEPOINTS;
}

static void tracepoint_lookup(struct tracepoint *tp, void *priv)
{
	int i;
	struct tracepoints_probe *tps = priv;

	if (is_tracepoint_lookup_success(tps))
		return;

	for (i = 0; i < ARRAY_SIZE(tps->tp_names); i++) {
		if (tps->tps[i] || strcmp(tp->name, tps->tp_names[i]))
			continue;
		tps->tps[i] = tp;
		tps->num_initalized++;
	}
}

static int trace_pid_show(struct seq_file *m, void *ptr)
{
	struct runqlat_info *info = m->private;

	seq_printf(m, "%d\n", info->pid);

	return 0;
}

static ssize_t trace_pid_store(void *priv, const char __user *buf, size_t count)
{
	int pid;
	struct runqlat_info *info = priv;

	if (kstrtoint_from_user(buf, count, 0, &pid))
		return -EINVAL;

	if (info->pid != INVALID_PID && pid != INVALID_PID)
		return -EPERM;

	local_irq_disable();
	arch_spin_lock(&info->lock);
	if (info->pid == pid)
		goto unlock;

	if (pid != INVALID_PID) {

		info->nr_trace = 0;
		info->nr_task = 0;
		memset(info->trace_entries, 0,
		       MAX_TRACE_ENTRIES * sizeof(struct trace_entry) +
		       MAX_TRACE_ENTRY_TASKS * sizeof(struct task_entry));
		sysak_module_get(&runqlat_ref);
	} else 
		sysak_module_put(&runqlat_ref);

	runqlat_info_reset(info);
	smp_wmb();
	info->pid = pid;
unlock:
	arch_spin_unlock(&info->lock);
	local_irq_enable();

	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(trace_pid);

static int threshold_show(struct seq_file *m, void *ptr)
{
	struct runqlat_info *info = m->private;

	seq_printf(m, "%llu\n", info->threshold);

	return 0;
}

static ssize_t threshold_store(void *priv, const char __user *buf, size_t count)
{
	unsigned long threshold;
	struct runqlat_info *info = priv;

	if (kstrtoul_from_user(buf, count, 0, &threshold))
		return -EINVAL;

	info->threshold = threshold;

	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(threshold);

static int runqlat_show(struct seq_file *m, void *ptr)
{
	int i, j;
	struct runqlat_info *info = m->private;

	if (info->pid != INVALID_CPU)
		return -EPERM;

	local_irq_disable();
	arch_spin_lock(&info->lock);
	for (i = 0; i < info->nr_trace; i++) {
		struct trace_entry *entry = info->trace_entries + i;

		seq_printf(m, "%*clatency(us):%llu\trunqlen:%d\trqstart(us):%llu\n", 2, ' ',
			   entry->latency / 1000, entry->nr_tasks, 
			   entry->rq_start / 1000);

		for (j = 0; j < entry->nr_tasks; j++) {
			struct task_entry *task = entry->entries + j;

			seq_printf(m, "%*cCOMM:%s\tPID:%d\tRUNTIME(us):%llu\n",
				   6, ' ', task->comm, task->pid,
				   task->runtime / 1000);
		}
		seq_putc(m, '\n');
	}
	arch_spin_unlock(&info->lock);
	local_irq_enable();

	return 0;
}

static ssize_t runqlat_store(void *priv, const char __user *buf, size_t count)
{
	int clear;
	struct runqlat_info *info = priv;

	if (kstrtoint_from_user(buf, count, 10, &clear) || clear != 0)
		return -EINVAL;

	local_irq_disable();
	arch_spin_lock(&info->lock);
	info->nr_trace = 0;
	info->nr_task = 0;
	memset(info->trace_entries, 0,
			MAX_TRACE_ENTRIES * sizeof(struct trace_entry) +
			MAX_TRACE_ENTRY_TASKS * sizeof(struct task_entry));
		
	runqlat_info_reset(info);
	smp_wmb();
	arch_spin_unlock(&info->lock);
	local_irq_enable();

	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(runqlat);

int trace_runqlat_init(struct proc_dir_entry *root_dir)
{
	int i;
	void *buf;
	int ret = -ENOMEM;
	struct tracepoints_probe *tps = &tps_probe;
	struct proc_dir_entry *parent_dir;
	struct runqlat_info *info = &runqlat_info;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	if (runq_init_local_tracepoints())
		return -ENODEV;
#endif

	buf = vzalloc(MAX_TRACE_ENTRIES * sizeof(struct trace_entry) +
		      MAX_TRACE_ENTRY_TASKS * sizeof(struct task_entry));
	if (!buf)
		return -ENOMEM;
	info->trace_entries = buf;
	info->task_entries = (void *)(info->trace_entries + MAX_TRACE_ENTRIES);

	parent_dir = proc_mkdir("runqlat", root_dir);
	if (!parent_dir)
		goto free_buf;

	if (!proc_create_data("pid", 0644, parent_dir, &trace_pid_fops, info))
		goto remove_proc;

	if (!proc_create_data("threshold", 0644, parent_dir, &threshold_fops,
			      info))
		goto remove_proc;

	if (!proc_create_data("runqlat", 0, parent_dir, &runqlat_fops, info))
		goto remove_proc;

	/* Lookup for the tracepoint that we needed */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	runq_for_each_kernel_tracepoint(tracepoint_lookup, tps);
#else
	for_each_kernel_tracepoint(tracepoint_lookup, tps);
#endif

	if (!is_tracepoint_lookup_success(tps))
		goto remove_proc;

	for (i = 0; i < PROBE_TRACEPOINTS; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		ret = tracepoint_probe_register(tps->tps[i]->name, tps->tp_probes[i],
						tps->priv);
#else
		ret = tracepoint_probe_register(tps->tps[i], tps->tp_probes[i],
						tps->priv);
#endif
		if (ret) {
			pr_err("sched trace: can not activate tracepoint "
			       "probe to %s\n", tps->tp_names[i]);
			while (i--)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
				tracepoint_probe_unregister(tps->tps[i]->name,
							    tps->tp_probes[i],
							    tps->priv);
#else
				tracepoint_probe_unregister(tps->tps[i],
							    tps->tp_probes[i],
							    tps->priv);
#endif
			goto remove_proc;
		}
	}

	return 0;
remove_proc:
	remove_proc_subtree("runqlat", root_dir);
free_buf:
	vfree(buf);

	return ret;
}

void trace_runqlat_exit(void)
{
	int i;
	struct tracepoints_probe *tps = &tps_probe;
	struct runqlat_info *info = &runqlat_info;

	for (i = 0; i < PROBE_TRACEPOINTS; i++)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		tracepoint_probe_unregister(tps->tps[i]->name, tps->tp_probes[i],
					    tps->priv);
#else
		tracepoint_probe_unregister(tps->tps[i], tps->tp_probes[i],
					    tps->priv);
#endif

	tracepoint_synchronize_unregister();
	vfree(info->trace_entries);
}
