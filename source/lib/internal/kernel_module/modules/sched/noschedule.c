#define pr_fmt(fmt) "trace-nosched: " fmt

#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/timer.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <trace/events/sched.h>
#include <asm/irq_regs.h>
#include "sysak_mods.h"
#include "common/proc.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#include <linux/sched.h>
#else
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/stat.h>
#endif

//#define CONFIG_DEBUG_TRACE_NOSCHED
#define NUMBER_CHARACTER		40
#define PROC_DIR_NAME			"nosch"
#define NUM_TRACEPOINTS			1
#define MAX_TRACE_ENTRIES		(SZ_1K / sizeof(void *))
#define PER_TRACE_ENTRIES_AVERAGE	8

#define MAX_STACE_TRACE_ENTRIES		\
	(MAX_TRACE_ENTRIES / PER_TRACE_ENTRIES_AVERAGE)


/**
 * If we call register_trace_sched_{wakeup,wakeup_new,switch,migrate_task}()
 * directly in a kernel module, the compiler will complain about undefined
 * symbol of __tracepoint_sched_{wakeup, wakeup_new, switch, migrate_task}
 * because the kernel do not export the tracepoint symbol. Here is a workaround
 * via for_each_kernel_tracepoint() to lookup the tracepoint and save.
 */
struct tracepoint_entry {
	void *probe;
	const char *name;
	struct tracepoint *tp;
};

struct stack_entry {
	unsigned int nr_entries;
	unsigned long *entries;
};

struct per_cpu_stack_trace {
	u64 last_timestamp;
	struct hrtimer hrtimer;
	struct task_struct *skip;

	unsigned int nr_stack_entries;
	unsigned int nr_entries;
	struct stack_entry stack_entries[MAX_STACE_TRACE_ENTRIES];
	unsigned long entries[MAX_TRACE_ENTRIES];

	char comms[MAX_STACE_TRACE_ENTRIES][TASK_COMM_LEN];
	pid_t pids[MAX_STACE_TRACE_ENTRIES];
	u64 duration[MAX_STACE_TRACE_ENTRIES];
	u64 stamp[MAX_STACE_TRACE_ENTRIES];
};

struct noschedule_info {
	struct tracepoint_entry tp_entries[NUM_TRACEPOINTS];
	unsigned int tp_initalized;

	struct per_cpu_stack_trace __percpu *stack_trace;
};

static int nosched_ref;

/* Whether to enable the tracker. */
static bool trace_enable;

/* Default sampling period is 4 000 000ns. The minimum value is 1000000ns. */
static u64 sampling_period = 4 * 1000 * 1000UL;

/**
 * How many nanoseconds should we record the stack trace.
 * Default is 10 000 000ns.
 */
static u64 duration_threshold = 10 * 1000 * 1000UL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
static void (*save_stack_trace_effective)(struct pt_regs *regs,
					  struct stack_trace *trace);

static inline void stack_trace_skip_hardirq_init(void)
{
	save_stack_trace_effective =
			(void *)kallsyms_lookup_name("save_stack_trace_regs");
}

static inline void store_stack_trace(struct pt_regs *regs,
				     struct stack_entry *stack_entry,
				     unsigned long *entries,
				     unsigned int max_entries, int skip)
{
	struct stack_trace stack_trace;

	stack_trace.nr_entries = 0;
	stack_trace.max_entries = max_entries;
	stack_trace.entries = entries;
	stack_trace.skip = skip;

	if (likely(regs && save_stack_trace_effective))
		save_stack_trace_effective(regs, &stack_trace);
	else
		save_stack_trace(&stack_trace);

	stack_entry->entries = entries;
	stack_entry->nr_entries = stack_trace.nr_entries;

	/*
	 * Some daft arches put -1 at the end to indicate its a full trace.
	 *
	 * <rant> this is buggy anyway, since it takes a whole extra entry so a
	 * complete trace that maxes out the entries provided will be reported
	 * as incomplete, friggin useless </rant>.
	 */
	if (stack_entry->nr_entries != 0 &&
	    stack_entry->entries[stack_entry->nr_entries - 1] == ULONG_MAX)
		stack_entry->nr_entries--;
}
#else
static unsigned int (*stack_trace_save_skip_hardirq)(struct pt_regs *regs,
						     unsigned long *store,
						     unsigned int size,
						     unsigned int skipnr);

static inline void stack_trace_skip_hardirq_init(void)
{
	stack_trace_save_skip_hardirq =
			(void *)kallsyms_lookup_name("stack_trace_save_regs");
}

static inline void store_stack_trace(struct pt_regs *regs,
				     struct stack_entry *stack_entry,
				     unsigned long *entries,
				     unsigned int max_entries, int skip)
{
	stack_entry->entries = entries;
	if (regs && stack_trace_save_skip_hardirq)
		stack_entry->nr_entries = stack_trace_save_skip_hardirq(regs,
				entries, max_entries, skip);
	else
		stack_entry->nr_entries = stack_trace_save(entries, max_entries,
							   skip);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static struct tracepoint **nosch__start___tracepoints_ptrs;
static struct tracepoint **nosch__stop___tracepoints_ptrs;

static int nosch_init_local_tracepoints(void)
{
	nosch__start___tracepoints_ptrs = (void *)kallsyms_lookup_name("__start___tracepoints_ptrs");
	nosch__stop___tracepoints_ptrs  = (void *)kallsyms_lookup_name("__stop___tracepoints_ptrs");
	if (nosch__start___tracepoints_ptrs == NULL || nosch__stop___tracepoints_ptrs == NULL) {
		return -1;
	}
	return 0;
}

static void nosch_for_each_tracepoint_range(struct tracepoint * const *begin,
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
 * nosch_for_each_kernel_tracepoint - iteration on all kernel tracepoints
 * @fct: callback
 * @priv: private data
 */
void nosch_for_each_kernel_tracepoint(void (*fct)(struct tracepoint *tp, void *priv),
		void *priv)
{
	nosch_for_each_tracepoint_range(nosch__start___tracepoints_ptrs,
		nosch__stop___tracepoints_ptrs, fct, priv);
}
#endif

static bool __stack_trace_record(struct per_cpu_stack_trace *stack_trace,
				 struct pt_regs *regs, u64 duration)
{
	unsigned int nr_entries, nr_stack_entries;
	struct stack_entry *stack_entry;

	nr_stack_entries = stack_trace->nr_stack_entries;
	if (nr_stack_entries >= ARRAY_SIZE(stack_trace->stack_entries))
		return false;

	nr_entries = stack_trace->nr_entries;
	if (nr_entries >= ARRAY_SIZE(stack_trace->entries))
		return false;

	/* Save the thread command, pid and duration. */
	strlcpy(stack_trace->comms[nr_stack_entries], current->comm,
		TASK_COMM_LEN);
	stack_trace->pids[nr_stack_entries] = current->pid;
	stack_trace->duration[nr_stack_entries] = duration;
	stack_trace->stamp[nr_stack_entries] = stack_trace->last_timestamp/1000;

	stack_entry = stack_trace->stack_entries + nr_stack_entries;
	store_stack_trace(regs, stack_entry, stack_trace->entries + nr_entries,
			  ARRAY_SIZE(stack_trace->entries) - nr_entries, 0);
	stack_trace->nr_entries += stack_entry->nr_entries;

	/**
	 * Ensure that the initialisation of @stack_entry is complete before we
	 * update the @nr_stack_entries.
	 */
	smp_store_release(&stack_trace->nr_stack_entries, nr_stack_entries + 1);

	if (unlikely(stack_trace->nr_entries >=
		     ARRAY_SIZE(stack_trace->entries))) {
		pr_info("BUG: MAX_TRACE_ENTRIES too low on cpu: %d!\n",
			smp_processor_id());

		return false;
	}

	return true;
}

/* Note: Must be called with irq disabled. */
static inline bool stack_trace_record(struct per_cpu_stack_trace *stack_trace,
				      u64 delta)
{
	if (unlikely(delta >= duration_threshold))
		return __stack_trace_record(stack_trace, get_irq_regs(), delta);

	return false;
}

static enum hrtimer_restart trace_nosched_hrtimer_handler(struct hrtimer *hrtimer)
{
	struct pt_regs *regs = get_irq_regs();
	struct per_cpu_stack_trace *stack_trace;
	u64 now = local_clock();

	stack_trace = container_of(hrtimer, struct per_cpu_stack_trace,
				   hrtimer);
	/**
	 * Skip the idle task and make sure we are not only the
	 * running task on the CPU. If we are interrupted from
	 * user mode, it indicate that we are not executing in
	 * the kernel space, so we should also skip it.
	 */
	if (!is_idle_task(current) && regs && !user_mode(regs) &&
	    !single_task_running()) {
		u64 delta;

		delta = now - stack_trace->last_timestamp;
		if (!stack_trace->skip && stack_trace_record(stack_trace, delta))
			stack_trace->skip = current;
	} else {
		stack_trace->last_timestamp = now;
	}

	hrtimer_forward_now(hrtimer, ns_to_ktime(sampling_period));

	return HRTIMER_RESTART;
}

/* interrupts should be disabled from __schedule() */
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
	u64 now = local_clock();
	struct per_cpu_stack_trace __percpu *stack_trace = priv;
	struct per_cpu_stack_trace *cpu_stack_trace = this_cpu_ptr(stack_trace);
	u64 last = cpu_stack_trace->last_timestamp;

	if (unlikely(!trace_enable))
		return;

	cpu_stack_trace->last_timestamp = now;
	if (unlikely(cpu_stack_trace->skip)) {
		unsigned int index = cpu_stack_trace->nr_stack_entries - 1;

		cpu_stack_trace->skip = NULL;
		cpu_stack_trace->duration[index] = now - last;
	}

}

static struct noschedule_info nosched_info = {
	.tp_entries = {
		[0] = {
			.name	= "sched_switch",
			.probe	= probe_sched_switch,
		},
	},
	.tp_initalized = 0,
};

static inline bool is_tracepoint_lookup_success(struct noschedule_info *info)
{
	return info->tp_initalized == ARRAY_SIZE(info->tp_entries);
}

static void tracepoint_lookup(struct tracepoint *tp, void *priv)
{
	int i;
	struct noschedule_info *info = priv;

	if (is_tracepoint_lookup_success(info))
		return;

	for (i = 0; i < ARRAY_SIZE(info->tp_entries); i++) {
		if (info->tp_entries[i].tp || !info->tp_entries[i].name ||
		    strcmp(tp->name, info->tp_entries[i].name))
			continue;
		info->tp_entries[i].tp = tp;
		info->tp_initalized++;
	}
}

static int threshold_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%llu\n", duration_threshold);

	return 0;
}

static ssize_t threshold_store(void *priv, const char __user *buf, size_t count)
{
	u64 val;

	if (kstrtou64_from_user(buf, count, 0, &val))
		return -EINVAL;

	duration_threshold = val;

	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(threshold);

static int enable_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%s\n", trace_enable ? "enabled" : "disabled");

	return 0;
}

static void each_hrtimer_start(void *priv)
{
	u64 now = local_clock();
	struct per_cpu_stack_trace __percpu *stack_trace = priv;
	struct hrtimer *hrtimer = this_cpu_ptr(&stack_trace->hrtimer);

	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
	hrtimer->function = trace_nosched_hrtimer_handler;

	__this_cpu_write(stack_trace->last_timestamp, now);

	hrtimer_start_range_ns(hrtimer, ns_to_ktime(sampling_period), 0,
			       HRTIMER_MODE_REL_PINNED);
}

static inline void trace_nosched_hrtimer_start(void)
{
	on_each_cpu(each_hrtimer_start, nosched_info.stack_trace, true);
}

static inline void trace_nosched_hrtimer_cancel(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		hrtimer_cancel(per_cpu_ptr(&nosched_info.stack_trace->hrtimer,
					   cpu));
}

static int trace_nosched_register_tp(void)
{
	int i;
	struct noschedule_info *info = &nosched_info;

	for (i = 0; i < ARRAY_SIZE(info->tp_entries); i++) {
		int ret;
		struct tracepoint_entry *entry = info->tp_entries + i;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		ret = tracepoint_probe_register(entry->tp->name, entry->probe,
						info->stack_trace);
#else
		ret = tracepoint_probe_register(entry->tp, entry->probe,
						info->stack_trace);
#endif
		if (ret && ret != -EEXIST) {
			pr_err("sched trace: can not activate tracepoint "
			       "probe to %s with error code: %d\n",
			       entry->name, ret);
			while (i--) {
				entry = info->tp_entries + i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
				tracepoint_probe_unregister(entry->tp->name,
							    entry->probe,
							    info->stack_trace);
#else
				tracepoint_probe_unregister(entry->tp,
							    entry->probe,
							    info->stack_trace);
#endif
			}
			return ret;
		}
	}

	return 0;
}

static int trace_nosched_unregister_tp(void)
{
	int i;
	struct noschedule_info *info = &nosched_info;

	for (i = 0; i < ARRAY_SIZE(info->tp_entries); i++) {
		int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		ret = tracepoint_probe_unregister(info->tp_entries[i].tp->name,
						  info->tp_entries[i].probe,
						  info->stack_trace);
#else
		ret = tracepoint_probe_unregister(info->tp_entries[i].tp,
						  info->tp_entries[i].probe,
						  info->stack_trace);
#endif
		if (ret && ret != -ENOENT) {
			pr_err("sched trace: can not inactivate tracepoint "
			       "probe to %s with error code: %d\n",
			       info->tp_entries[i].name, ret);
			return ret;
		}
	}

	return 0;
}

static ssize_t enable_store(void *priv, const char __user *buf, size_t count)
{
	int enable;

	if (kstrtoint_from_user(buf, count, 16, &enable))
		return -EINVAL;

	if (!!enable == !!trace_enable)
		return count;

	if (enable) {
		if (!trace_nosched_register_tp()) {
			trace_nosched_hrtimer_start();
			sysak_module_get(&nosched_ref);
		}
		else
			return -EAGAIN;
	} else {
		trace_nosched_hrtimer_cancel();
		if (trace_nosched_unregister_tp())
			return -EAGAIN;
		sysak_module_put(&nosched_ref);
	}

	trace_enable = enable;
	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(enable);

static void each_stack_trace_clear(void *priv)
{
	struct per_cpu_stack_trace __percpu *stack_trace = priv;
	struct per_cpu_stack_trace *cpu_stack_trace = this_cpu_ptr(stack_trace);

	cpu_stack_trace->nr_entries = 0;
	cpu_stack_trace->nr_stack_entries = 0;
}

static inline void seq_print_stack_trace(struct seq_file *m,
					 struct stack_entry *entry)
{
	int i;

	if (WARN_ON(!entry->entries))
		return;

	for (i = 0; i < entry->nr_entries; i++)
		seq_printf(m, "%*c%pS\n", 5, ' ', (void *)entry->entries[i]);
}

static int stack_trace_show(struct seq_file *m, void *ptr)
{
	int cpu;
	struct per_cpu_stack_trace __percpu *stack_trace = m->private;

	for_each_online_cpu(cpu) {
		int i;
		unsigned int nr;
		struct per_cpu_stack_trace *cpu_stack_trace;

		cpu_stack_trace = per_cpu_ptr(stack_trace, cpu);

		/**
		 * Paired with smp_store_release() in the
		 * __stack_trace_record().
		 */
		nr = smp_load_acquire(&cpu_stack_trace->nr_stack_entries);
		if (!nr)
			continue;

//		seq_printf(m, " cpu: %d\n", cpu);

		for (i = 0; i < nr; i++) {
			struct stack_entry *entry;

			entry = cpu_stack_trace->stack_entries + i;
			seq_printf(m, "%*ccpu:%d\tCOMM: %s\tPID:%d\tDURATION:%lluus\tSTAMP:%llu\n",
				   5, ' ', cpu, cpu_stack_trace->comms[i],
				   cpu_stack_trace->pids[i],
				   cpu_stack_trace->duration[i] / (1000UL),
				   cpu_stack_trace->stamp[i]
				   );
			seq_print_stack_trace(m, entry);
			seq_putc(m, '\n');

			cond_resched();
		}
	}
	
	return 0;
}

static ssize_t stack_trace_store(void *priv, const char __user *buf,
				 size_t count)
{
	int clear;

	if (kstrtoint_from_user(buf, count, 10, &clear) || clear != 0)
		return -EINVAL;

	on_each_cpu(each_stack_trace_clear, priv, true);

	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(stack_trace);

#ifdef CONFIG_DEBUG_TRACE_NOSCHED
#include <linux/delay.h>

static int nosched_test_show(struct seq_file *m, void *ptr)
{
	return 0;
}

static ssize_t nosched_test_store(void *priv, const char __user *buf,
				  size_t count)
{
	int delay;

	if (kstrtoint_from_user(buf, count, 0, &delay) || delay == 0)
		return -EINVAL;

	mdelay(delay);

	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(nosched_test);
#endif

int trace_noschedule_init(struct proc_dir_entry *root_dir)
{
	struct proc_dir_entry *parent_dir;
	struct noschedule_info *info = &nosched_info;
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	if (nosch_init_local_tracepoints())
		return -ENODEV;
#endif
		
	stack_trace_skip_hardirq_init();

	/* Lookup for the tracepoint that we needed */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	nosch_for_each_kernel_tracepoint(tracepoint_lookup, info);
#else
	for_each_kernel_tracepoint(tracepoint_lookup, info);
#endif

	if (!is_tracepoint_lookup_success(info))
		return -ENODEV;

	info->stack_trace = alloc_percpu(struct per_cpu_stack_trace);
	if (!info->stack_trace)
		return -ENOMEM;

	parent_dir = proc_mkdir(PROC_DIR_NAME, root_dir);
	if (!parent_dir)
		goto free_buf;
	if (!proc_create_data("threshold", 0644, parent_dir, &threshold_fops,
			      info->stack_trace))
		goto remove_proc;
	if (!proc_create_data("enable", 0644, parent_dir, &enable_fops,
			      info->stack_trace))
		goto remove_proc;
	if (!proc_create_data("stack_trace", 0, parent_dir, &stack_trace_fops,
			      info->stack_trace))
		goto remove_proc;
#ifdef CONFIG_DEBUG_TRACE_NOSCHED
	if (!proc_create_data("nosched_test", 0644, parent_dir,
			      &nosched_test_fops, info->stack_trace))
		goto remove_proc;
#endif

	return 0;
remove_proc:
	remove_proc_subtree(PROC_DIR_NAME, root_dir);
free_buf:
	free_percpu(info->stack_trace);

	return -ENOMEM;
}

void trace_noschedule_exit(void)
{
	if (trace_enable) {
		trace_nosched_hrtimer_cancel();
		trace_nosched_unregister_tp();
		tracepoint_synchronize_unregister();
	}
	free_percpu(nosched_info.stack_trace);
}
