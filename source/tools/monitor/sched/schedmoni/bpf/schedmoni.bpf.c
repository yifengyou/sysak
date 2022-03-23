// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../schedmoni.h"
#include "../nosched.comm.h"

#define MAX_THRESH	(10*1000)
#define TASK_RUNNING	0
#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, struct args);
} argmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct enq_info);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct bpf_map_def SEC("maps") stackmap = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") stackmap_ext = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ext_key),
	.value_size = sizeof(struct ext_val),
	.max_entries = 10000,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_MONI_NR);
	__type(key, u64);
	__type(value, struct latinfo);
} info_map SEC(".maps");

/* 
 * the return value type can only be assigned to 0,
 * so it can be int ,long , long long and the unsinged version 
 * */
#define GETARG_FROM_ARRYMAP(map,argp,type,member)({	\
	type retval = 0;			\
	int i = 0;				\
	argp = bpf_map_lookup_elem(&map, &i);	\
	if (argp) {				\
		retval = _(argp->member);		\
	}					\
	retval;					\
	})

#define BPF_F_FAST_STACK_CMP	(1ULL << 9)
#define KERN_STACKID_FLAGS	(0 | BPF_F_FAST_STACK_CMP)

#define BIT_WORD(nr)	((nr) / BITS_PER_LONG)
#define BITS_PER_LONG	64

static inline int test_bit(int nr, const volatile unsigned long *addr)
{               
        return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline int test_ti_thread_flag(struct thread_info *ti, int nr)
{
	int result;
	unsigned long *addr;
	unsigned long tmp = _(ti->flags);

	addr = &tmp;
	result = 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
	return result;
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	struct thread_info tf, *tfp;

	tfp = &(tsk->thread_info);
	bpf_probe_read(&tf, sizeof(tf), &(tsk->thread_info));
	tfp = &tf;
	return test_ti_thread_flag(tfp, flag);
}

static inline int test_tsk_need_resched(struct task_struct *tsk, int flag)
{
	return test_tsk_thread_flag(tsk, flag);
}

/* record enqueue timestamp */
static __always_inline
int trace_enqueue(u32 tgid, u32 pid, unsigned int runqlen)
{
	struct enq_info enq_info;
	u64 ts;
	pid_t targ_tgid, targ_pid;
	struct args *argp;

	if (!pid)
		return 0;

	targ_tgid = GETARG_FROM_ARRYMAP(argmap, argp, pid_t, targ_tgid);
	targ_pid = GETARG_FROM_ARRYMAP(argmap, argp, pid_t, targ_pid);
	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	ts = bpf_ktime_get_ns();
	enq_info.ts = ts;
	enq_info.rqlen = runqlen;
	bpf_map_update_elem(&start, &pid, &enq_info, 0);
	return 0;
}

SEC("raw_tracepoint/sched_wakeup")
int raw_tracepoint__sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	unsigned int runqlen = 0;
	struct task_struct *p = (void *)ctx->args[0];

	runqlen = BPF_CORE_READ(p, se.cfs_rq, nr_running);
	return trace_enqueue(_(p->tgid), _(p->pid), runqlen);
}

SEC("raw_tracepoint/sched_wakeup_new")
int raw_tracepoint__sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
	unsigned int runqlen = 0;
	struct task_struct *p = (void *)ctx->args[0];

	runqlen = BPF_CORE_READ(p, se.cfs_rq, nr_running);
	return trace_enqueue(_(p->tgid), _(p->pid), runqlen);
}

SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
	struct task_struct *prev;
	struct enq_info *enq;
	u64 cpuid;
	u32 pid, prev_pid;
	long int prev_state;
	struct event event = {};
	u64 delta_us, min_us;
	struct args *argp;
	struct latinfo *latp;
	struct latinfo lati;

	prev_pid = ctx->prev_pid;
	pid = ctx->next_pid;
	prev_state = ctx->prev_state;

	cpuid = bpf_get_smp_processor_id();
	/* 1rst: nosched */
	latp = bpf_map_lookup_elem(&info_map, &cpuid);
	if (latp) {
		latp->last_seen_need_resched_ns = 0;
	} else {

		__builtin_memset(&lati, 0, sizeof(struct latinfo));
		lati.last_seen_need_resched_ns = 0;
		lati.ticks_without_resched = 0;
		bpf_map_update_elem(&info_map, &cpuid, &lati, BPF_ANY);
	}

	/* 2nd: runqslower */
	/* ivcsw: treat like an enqueue event and store timestamp */
	prev = (void *)bpf_get_current_task();
	if (prev_state == TASK_RUNNING) {
		unsigned int runqlen = 0;

		runqlen = BPF_CORE_READ(prev, se.cfs_rq, nr_running);
		return trace_enqueue(_(prev->tgid), _(prev->pid), runqlen);
	}
	/* fetch timestamp and calculate delta */
	enq = bpf_map_lookup_elem(&start, &pid);
	if (!enq)
		return 0;   /* missed enqueue */

	delta_us = (bpf_ktime_get_ns() - _(enq->ts)) / 1000;
	min_us = GETARG_FROM_ARRYMAP(argmap, argp, u64, min_us);
	if (min_us && delta_us <= min_us)
		return 0;

	__builtin_memset(&event, 0, sizeof(struct event));
	event.cpuid = cpuid;
	event.pid = pid;
	event.prev_pid = prev_pid;
	event.delta_us = delta_us;
	event.rqlen = _(enq->rqlen);
	bpf_probe_read(event.task, sizeof(event.task), &(ctx->next_comm));
	bpf_probe_read(event.prev_task, sizeof(event.prev_task), &(ctx->prev_comm));
	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);

	return 0;
}

static inline u64 adjust_thresh(u64 min_us)
{
	if (min_us > MAX_THRESH)
		min_us = MAX_THRESH;

	return min_us;
}

SEC("kprobe/account_process_tick")
int BPF_KPROBE(account_process_tick, struct task_struct *p, int user_tick)
{
	int args_key;
	u64 cpuid, min_us;
	u64 resched_latency, now;
	struct latinfo lati, *latp;
	struct args args, *argsp;

	__builtin_memset(&args_key, 0, sizeof(int));
	argsp = bpf_map_lookup_elem(&argmap, &args_key);
	if (!argsp)
		return 0;

	if(!test_tsk_need_resched(p, _(argsp->flag)))
		return 0;

	now = bpf_ktime_get_ns();

	__builtin_memset(&cpuid, 0, sizeof(u64));
	cpuid = bpf_get_smp_processor_id();
	latp = bpf_map_lookup_elem(&info_map, &cpuid);
	if (latp) {
		if (!latp->last_seen_need_resched_ns) {
			latp->last_seen_need_resched_ns = now;
			latp->ticks_without_resched = 0;
		} else {
			latp->ticks_without_resched++;
			resched_latency = (now - latp->last_seen_need_resched_ns)/1000;
			min_us = adjust_thresh(_(argsp->min_us));
			if (resched_latency > min_us) {
				struct key_t key;
				struct ext_key ext_key;
				struct ext_val ext_val;

				__builtin_memset(&key, 0, sizeof(struct key_t));
				__builtin_memset(&ext_key, 0, sizeof(struct ext_key));
				__builtin_memset(&ext_val, 0, sizeof(struct ext_val));
				key.ret = bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
				ext_key.stamp = now;
				ext_key.ret = key.ret;
				ext_val.lat_us = resched_latency;
				bpf_get_current_comm(&ext_val.comm, sizeof(ext_val.comm));
				ext_val.pid = bpf_get_current_pid_tgid();
				ext_val.nosched_ticks = latp->ticks_without_resched;
				ext_val.cpu = cpuid;
				ext_val.stamp = latp->last_seen_need_resched_ns;
				bpf_map_update_elem(&stackmap_ext, &ext_key, &ext_val, BPF_ANY);
			}
		}
	} else {
		__builtin_memset(&lati, 0, sizeof(struct latinfo));
		lati.last_seen_need_resched_ns = now;
		lati.ticks_without_resched = 0;
		bpf_map_update_elem(&info_map, &cpuid, &lati, BPF_ANY);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
