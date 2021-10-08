#define pr_fmt(fmt) "trace-irqoff: " fmt

#include <linux/hrtimer.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <asm/irq_regs.h>
#include "sysak_mods.h"
#include "common/proc.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#include <linux/sched.h>
#else
#include <linux/sched/clock.h>
#endif

#define MAX_TRACE_ENTRIES		(SZ_1K / sizeof(unsigned long))
#define PER_TRACE_ENTRIES_AVERAGE	(8 + 8)

#define MAX_STACE_TRACE_ENTRIES		\
	(MAX_TRACE_ENTRIES / PER_TRACE_ENTRIES_AVERAGE)

#define MAX_LATENCY_RECORD		10

static int irqoff_ref;
static bool trace_enable;

/**
 * Default sampling period is 4,000,000ns. The minimum value is 1,000,000ns.
 */
static u64 sampling_period = 4 * 1000 * 1000UL;

/**
 * How many times should we record the stack trace.
 * Default is 10,000,000ns.
 */
static u64 trace_irqoff_latency = 10 * 1000 * 1000UL;

struct irqoff_trace {
	unsigned int nr_entries;
	unsigned long *entries;
};

struct stack_trace_metadata {
	u64 last_timestamp;
	unsigned long nr_irqoff_trace;
	struct irqoff_trace trace[MAX_STACE_TRACE_ENTRIES];
	unsigned long nr_entries;
	unsigned long entries[MAX_TRACE_ENTRIES];
	unsigned long latency_count[MAX_LATENCY_RECORD];

	/* Task command names*/
	char comms[MAX_STACE_TRACE_ENTRIES][TASK_COMM_LEN];

	/* Task pids*/
	pid_t pids[MAX_STACE_TRACE_ENTRIES];

	struct {
		u64 nsecs:63;
		u64 more:1;
	} latency[MAX_STACE_TRACE_ENTRIES];
	u64	stamp[MAX_STACE_TRACE_ENTRIES];
};

struct per_cpu_stack_trace {
	struct timer_list timer;
	struct hrtimer hrtimer;
	struct stack_trace_metadata hardirq_trace;
	struct stack_trace_metadata softirq_trace;

	bool softirq_delayed;
};

static struct per_cpu_stack_trace __percpu *cpu_stack_trace;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
static void (*save_stack_trace_skip_hardirq)(struct pt_regs *regs,
					     struct stack_trace *trace);

static inline void stack_trace_skip_hardirq_init(void)
{
	save_stack_trace_skip_hardirq =
			(void *)kallsyms_lookup_name("save_stack_trace_regs");
}

static inline void store_stack_trace(struct pt_regs *regs,
				     struct irqoff_trace *trace,
				     unsigned long *entries,
				     unsigned int max_entries, int skip)
{
	struct stack_trace stack_trace;

	stack_trace.nr_entries = 0;
	stack_trace.max_entries = max_entries;
	stack_trace.entries = entries;
	stack_trace.skip = skip;

	if (regs && save_stack_trace_skip_hardirq)
		save_stack_trace_skip_hardirq(regs, &stack_trace);
	else
		save_stack_trace(&stack_trace);

	trace->entries = entries;
	trace->nr_entries = stack_trace.nr_entries;

	/*
	 * Some daft arches put -1 at the end to indicate its a full trace.
	 *
	 * <rant> this is buggy anyway, since it takes a whole extra entry so a
	 * complete trace that maxes out the entries provided will be reported
	 * as incomplete, friggin useless </rant>.
	 */
	if (trace->nr_entries != 0 &&
	    trace->entries[trace->nr_entries - 1] == ULONG_MAX)
		trace->nr_entries--;
}
#else
static unsigned int (*stack_trace_save_skip_hardirq)(struct pt_regs *regs,
						     unsigned long *store,
						     unsigned int size,
						     unsigned int skipnr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static inline void stack_trace_skip_hardirq_init(void)
{
	stack_trace_save_skip_hardirq =
			(void *)kallsyms_lookup_name("stack_trace_save_regs");
}
#else /* LINUX_VERSION_CODE */

static int noop_pre_handler(struct kprobe *p, struct pt_regs *regs){
	return 0;
}

/**
 *
 * We can only find the kallsyms_lookup_name's addr by using kprobes, then use
 * the unexported kallsyms_lookup_name to find symbols.
 */
static void stack_trace_skip_hardirq_init(void)
{
	int ret;
	struct kprobe kp;
	unsigned long (*kallsyms_lookup_name_fun)(const char *name);


	ret = -1;
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = noop_pre_handler;
	stack_trace_save_skip_hardirq = NULL;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		return;
	}

	kallsyms_lookup_name_fun = (void*)kp.addr;
	unregister_kprobe(&kp);

	stack_trace_save_skip_hardirq =
		(void *)kallsyms_lookup_name_fun("stack_trace_save_regs");
}
#endif  /* LINUX_VERSION_CODE */

static inline void store_stack_trace(struct pt_regs *regs,
				     struct irqoff_trace *trace,
				     unsigned long *entries,
				     unsigned int max_entries, int skip)
{
	trace->entries = entries;
	if (regs && stack_trace_save_skip_hardirq)
		trace->nr_entries = stack_trace_save_skip_hardirq(regs, entries,
								  max_entries,
								  skip);
	else
		trace->nr_entries = stack_trace_save(entries, max_entries,
						     skip);
}
#endif

/**
 * Note: Must be called with irq disabled.
 */
static bool save_trace(struct pt_regs *regs, bool hardirq, u64 latency, u64 stamp)
{
	unsigned long nr_entries, nr_irqoff_trace;
	struct irqoff_trace *trace;
	struct stack_trace_metadata *stack_trace;

	stack_trace = hardirq ? this_cpu_ptr(&cpu_stack_trace->hardirq_trace) :
		      this_cpu_ptr(&cpu_stack_trace->softirq_trace);

	nr_irqoff_trace = stack_trace->nr_irqoff_trace;
	if (unlikely(nr_irqoff_trace >= MAX_STACE_TRACE_ENTRIES))
		return false;

	nr_entries = stack_trace->nr_entries;
	if (unlikely(nr_entries >= MAX_TRACE_ENTRIES - 1))
		return false;

	strlcpy(stack_trace->comms[nr_irqoff_trace], current->comm,
		TASK_COMM_LEN);
	stack_trace->pids[nr_irqoff_trace] = current->pid;
	stack_trace->latency[nr_irqoff_trace].nsecs = latency;
	stack_trace->latency[nr_irqoff_trace].more = !hardirq && regs;
	stack_trace->stamp[nr_irqoff_trace] = stamp;

	trace = stack_trace->trace + nr_irqoff_trace;
	store_stack_trace(regs, trace, stack_trace->entries + nr_entries,
			  MAX_TRACE_ENTRIES - nr_entries, 0);
	stack_trace->nr_entries += trace->nr_entries;

	/**
	 * Ensure that the initialisation of @trace is complete before we
	 * update the @nr_irqoff_trace.
	 */
	smp_store_release(&stack_trace->nr_irqoff_trace, nr_irqoff_trace + 1);

	if (unlikely(stack_trace->nr_entries >= MAX_TRACE_ENTRIES - 1)) {
		pr_info("BUG: MAX_TRACE_ENTRIES too low!");

		return false;
	}

	return true;
}

static bool trace_irqoff_record(u64 delta, bool hardirq, bool skip, u64 stamp)
{
	int index = 0;
	u64 throttle = sampling_period << 1;
	u64 delta_old = delta;

	if (delta < throttle)
		return false;

	delta >>= 1;
	while (delta > throttle) {
		index++;
		delta >>= 1;
	}

	if (unlikely(index >= MAX_LATENCY_RECORD))
		index = MAX_LATENCY_RECORD - 1;

	if (hardirq)
		__this_cpu_inc(cpu_stack_trace->hardirq_trace.latency_count[index]);
	else if (!skip)
		__this_cpu_inc(cpu_stack_trace->softirq_trace.latency_count[index]);

	if (unlikely(delta_old >= trace_irqoff_latency))
		save_trace(skip ? get_irq_regs() : NULL, hardirq, delta_old, stamp);

	return true;
}

static enum hrtimer_restart trace_irqoff_hrtimer_handler(struct hrtimer *hrtimer)
{
	u64 now = local_clock(), delta, stamp;

	stamp = __this_cpu_read(cpu_stack_trace->hardirq_trace.last_timestamp);
	delta = now - stamp;
	__this_cpu_write(cpu_stack_trace->hardirq_trace.last_timestamp, now);

	if (trace_irqoff_record(delta, true, true, stamp)) {
		__this_cpu_write(cpu_stack_trace->softirq_trace.last_timestamp,
				 now);
	} else if (!__this_cpu_read(cpu_stack_trace->softirq_delayed)) {
		u64 delta_soft;

		stamp = __this_cpu_read(cpu_stack_trace->softirq_trace.last_timestamp);
		delta_soft = now - stamp;
			
		if (unlikely(delta_soft >= trace_irqoff_latency)) {
			__this_cpu_write(cpu_stack_trace->softirq_delayed, true);
			trace_irqoff_record(delta_soft, false, true, stamp);
		}
	}

	hrtimer_forward_now(hrtimer, ns_to_ktime(sampling_period));

	return HRTIMER_RESTART;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
static void trace_irqoff_timer_handler(unsigned long data)
#else
static void trace_irqoff_timer_handler(struct timer_list *timer)
#endif
{
	u64 now = local_clock(), delta, stamp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
	struct timer_list *timer = (struct timer_list *)data;
#endif
	
	stamp = __this_cpu_read(cpu_stack_trace->softirq_trace.last_timestamp);
	delta = now - stamp;
	__this_cpu_write(cpu_stack_trace->softirq_trace.last_timestamp, now);

	__this_cpu_write(cpu_stack_trace->softirq_delayed, false);

	trace_irqoff_record(delta, false, false, stamp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	mod_timer_pinned(timer,
			 jiffies + msecs_to_jiffies(sampling_period / 1000000UL));
#else
	mod_timer(timer,
		  jiffies + msecs_to_jiffies(sampling_period / 1000000UL));
#endif
}

static void smp_clear_stack_trace(void *info)
{
	int i;
	struct per_cpu_stack_trace *stack_trace = info;

	stack_trace->hardirq_trace.nr_entries = 0;
	stack_trace->hardirq_trace.nr_irqoff_trace = 0;
	stack_trace->softirq_trace.nr_entries = 0;
	stack_trace->softirq_trace.nr_irqoff_trace = 0;

	for (i = 0; i < MAX_LATENCY_RECORD; i++) {
		stack_trace->hardirq_trace.latency_count[i] = 0;
		stack_trace->softirq_trace.latency_count[i] = 0;
	}
}

static void smp_timers_start(void *info)
{
	u64 now = local_clock();
	struct per_cpu_stack_trace *stack_trace = info;
	struct hrtimer *hrtimer = &stack_trace->hrtimer;
	struct timer_list *timer = &stack_trace->timer;

	stack_trace->hardirq_trace.last_timestamp = now;
	stack_trace->softirq_trace.last_timestamp = now;

	hrtimer_start_range_ns(hrtimer, ns_to_ktime(sampling_period),
			       0, HRTIMER_MODE_REL_PINNED);

	timer->expires = jiffies + msecs_to_jiffies(sampling_period / 1000000UL);
	add_timer_on(timer, smp_processor_id());
}


static void seq_print_stack_trace(struct seq_file *m, struct irqoff_trace *trace)
{
	int i;

	if (WARN_ON(!trace->entries))
		return;

	for (i = 0; i < trace->nr_entries; i++)
		seq_printf(m, "%*c%pS\n", 5, ' ', (void *)trace->entries[i]);
}

static void trace_latency_show_one(struct seq_file *m, void *v, bool hardirq)
{
	int cpu;

	for_each_online_cpu(cpu) {
		int i;
		unsigned long nr_irqoff_trace;
		struct stack_trace_metadata *stack_trace;

		stack_trace = hardirq ?
			per_cpu_ptr(&cpu_stack_trace->hardirq_trace, cpu) :
			per_cpu_ptr(&cpu_stack_trace->softirq_trace, cpu);

		/**
		 * Paired with smp_store_release() in the save_trace().
		 */
		nr_irqoff_trace = smp_load_acquire(&stack_trace->nr_irqoff_trace);

		if (!nr_irqoff_trace)
			continue;

		for (i = 0; i < nr_irqoff_trace; i++) {
			struct irqoff_trace *trace = stack_trace->trace + i;

			seq_printf(m, "%*ccpu:%d\tCOMMAND:%s\tPID:%d\tLATENCY:%lu%s\tSTAMP:%llu\n",
				   5, ' ', cpu, stack_trace->comms[i],
				   stack_trace->pids[i],
				   stack_trace->latency[i].nsecs / (1000 * 1000UL),
				   stack_trace->latency[i].more ? "+ms" : "ms",
				   stack_trace->stamp[i] / 1000UL);
			seq_print_stack_trace(m, trace);
			seq_putc(m, '\n');

			cond_resched();
		}
	}
}

static int trace_latency_show(struct seq_file *m, void *v)
{
	int cpu;
	seq_printf(m, "trace_irqoff_latency: %llums\n\n",
		   trace_irqoff_latency / (1000 * 1000UL));

	seq_puts(m, " hardirq:\n");
	trace_latency_show_one(m, v, true);

	seq_puts(m, " softirq:\n");
	trace_latency_show_one(m, v, false);

	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, smp_clear_stack_trace,
				per_cpu_ptr(cpu_stack_trace, cpu),
				true);
	return 0;
}


static ssize_t trace_latency_store(void *priv, const char __user *buf, size_t count)
{
	unsigned long latency;

	if (kstrtoul_from_user(buf, count, 0, &latency))
		return -EINVAL;

	if (latency == 0) {
		int cpu;

		for_each_online_cpu(cpu)
			smp_call_function_single(cpu, smp_clear_stack_trace,
						 per_cpu_ptr(cpu_stack_trace, cpu),
						 true);
		return count;
	} else if (latency < (sampling_period << 1) / (1000 * 1000UL))
		return -EINVAL;

	trace_irqoff_latency = latency * 1000 * 1000UL;

	return count;
}

DEFINE_PROC_ATTRIBUTE_RW(trace_latency);

static void trace_irqoff_start_timers(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct hrtimer *hrtimer;
		struct timer_list *timer;

		hrtimer = per_cpu_ptr(&cpu_stack_trace->hrtimer, cpu);
		hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
		hrtimer->function = trace_irqoff_hrtimer_handler;

		timer = per_cpu_ptr(&cpu_stack_trace->timer, cpu);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
		__setup_timer(timer, trace_irqoff_timer_handler,
			      (unsigned long)timer, TIMER_IRQSAFE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
		timer->flags = TIMER_PINNED | TIMER_IRQSAFE;
		setup_timer(timer, trace_irqoff_timer_handler,
			    (unsigned long)timer);
#else
		timer_setup(timer, trace_irqoff_timer_handler,
			    TIMER_PINNED | TIMER_IRQSAFE);
#endif

		smp_call_function_single(cpu, smp_timers_start,
					 per_cpu_ptr(cpu_stack_trace, cpu),
					 true);
	}
}

static void trace_irqoff_cancel_timers(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct hrtimer *hrtimer;
		struct timer_list *timer;

		hrtimer = per_cpu_ptr(&cpu_stack_trace->hrtimer, cpu);
		hrtimer_cancel(hrtimer);

		timer = per_cpu_ptr(&cpu_stack_trace->timer, cpu);
		del_timer_sync(timer);
	}
}

static int enable_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%s\n", trace_enable ? "enabled" : "disabled");

	return 0;
}

static ssize_t enable_store(void *priv, const char __user *buf, size_t count)
{
	bool enable;

	if (kstrtobool_from_user(buf, count, &enable))
		return -EINVAL;

	if (!!enable == !!trace_enable)
		return count;

	if (enable) {
		trace_irqoff_start_timers();
		sysak_module_get(&irqoff_ref);
	}
	else {
		trace_irqoff_cancel_timers();
		sysak_module_put(&irqoff_ref);
	}

	trace_enable = enable;

	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(enable);

static int sampling_period_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%llums\n", sampling_period / (1000 * 1000UL));

	return 0;
}

static ssize_t sampling_period_store(void *priv, const char __user *buf, size_t count)
{
	unsigned long period;

	if (trace_enable)
		return -EINVAL;

	if (kstrtoul_from_user(buf, count, 0, &period))
		return -EINVAL;

	period *= 1000 * 1000UL;
	if (period > (trace_irqoff_latency >> 1))
		trace_irqoff_latency = period << 1;

	sampling_period = period;

	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(sampling_period);


extern int  trace_noschedule_init(struct proc_dir_entry *root_dir);
extern void trace_noschedule_exit(void);
extern int  trace_runqlat_init(struct proc_dir_entry *root_dir);
extern void trace_runqlat_exit(void);

int trace_irqoff_init(void)
{
	int ret;
	struct proc_dir_entry *root_dir = NULL;
	struct proc_dir_entry *parent_dir;

	cpu_stack_trace = alloc_percpu(struct per_cpu_stack_trace);
	if (!cpu_stack_trace)
		return -ENOMEM;

	stack_trace_skip_hardirq_init();
	
	root_dir = sysak_proc_mkdir("runlatency");
	if (!root_dir) {
		ret = -ENOMEM;
		goto free_percpu;
	}

	parent_dir = proc_mkdir("irqoff", root_dir);
	if (!parent_dir) {
		ret = -ENOMEM;
		goto remove_root;
	}

	if (!proc_create("latency", S_IRUSR | S_IWUSR, parent_dir,
			 &trace_latency_fops)){
		ret = -ENOMEM;
		goto remove_proc;
	}

	if (!proc_create("enable", S_IRUSR | S_IWUSR, parent_dir, &enable_fops)){
		ret = -ENOMEM;
		goto remove_proc;
	}


	if (!proc_create("period", S_IRUSR | S_IWUSR, parent_dir,
			 &sampling_period_fops)){
		ret = -ENOMEM;
		goto remove_proc;
	}
		
	ret = trace_noschedule_init(root_dir);
	if (ret){
		goto remove_proc;
	}
	
	ret = trace_runqlat_init(root_dir);
	if (ret){
		trace_noschedule_exit();
		goto remove_proc;
	}

	return 0;

remove_proc:
	remove_proc_subtree("irqoff", root_dir);
remove_root:
	sysak_remove_proc_entry("runlatency");
free_percpu:
	free_percpu(cpu_stack_trace);

	return -ENOMEM;
}

void trace_irqoff_exit(void)
{
	if (trace_enable)
		trace_irqoff_cancel_timers();
	trace_noschedule_exit();
	trace_runqlat_exit();
	free_percpu(cpu_stack_trace);
}

