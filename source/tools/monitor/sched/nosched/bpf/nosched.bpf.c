// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
/*
 * Todo: 1. how to distinguish CONFIG_THREAD_INFO_IN_TASK configured?
 *       2. why #ifdef __x86_64__ not work at nosched.bpf.c?
 *       3. some magic NUMBER, like max_entries, need to be configable
 * */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../nosched.comm.h"

#define BPF_F_FAST_STACK_CMP	(1ULL << 9)
#define KERN_STACKID_FLAGS	(0 | BPF_F_FAST_STACK_CMP)

#define BIT_WORD(nr)	((nr) / BITS_PER_LONG)
#define BITS_PER_LONG	64
#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct bpf_map_def SEC("maps") args_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct args),
	.max_entries = 1,
};

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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
//#ifdef CONFIG_THREAD_INFO_IN_TASK
	tfp = &(tsk->thread_info);
//#elif !defined(__HAVE_THREAD_FUNCTIONS)
//# define task_thread_info(task) ((struct thread_info *)(task)->stack)
//#endif
	bpf_probe_read(&tf, sizeof(tf), &(tsk->thread_info));
	tfp = &tf;
	return test_ti_thread_flag(tfp, flag);
}

static inline int test_tsk_need_resched(struct task_struct *tsk, int flag)
{
	return test_tsk_thread_flag(tsk, flag);
}

SEC("kprobe/account_process_tick")
int BPF_KPROBE(account_process_tick, struct task_struct *p, int user_tick)
{
	int args_key;
	u64 cpuid;
	u64 resched_latency, now;
	struct latinfo lati, *latp;
	struct args args, *argsp;

	__builtin_memset(&args_key, 0, sizeof(int));
	argsp = bpf_map_lookup_elem(&args_map, &args_key);
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
			resched_latency = now - latp->last_seen_need_resched_ns;
			if (resched_latency > _(argsp->thresh)) {
				struct key_t key;
				struct ext_key ext_key;
				struct ext_val ext_val;

				__builtin_memset(&key, 0, sizeof(struct key_t));
				__builtin_memset(&ext_key, 0, sizeof(struct ext_key));
				__builtin_memset(&ext_val, 0, sizeof(struct ext_val));
				key.ret = bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
				ext_key.stamp = now;
				ext_key.ret = key.ret;
				ext_val.lat_us = resched_latency/1000;
				bpf_get_current_comm(&ext_val.comm, sizeof(ext_val.comm));
				ext_val.pid = bpf_get_current_pid_tgid();
				ext_val.nosched_ticks = latp->ticks_without_resched;
				ext_val.cpu = cpuid;
				ext_val.stamp = latp->last_seen_need_resched_ns;
				bpf_map_update_elem(&stackmap_ext, &ext_key, &ext_val, BPF_ANY);
				bpf_printk("%s :lat is %ld us, %d ticks\n", ext_val.comm, 
					resched_latency/1000, latp->ticks_without_resched);
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

/*
struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};
 */
SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
	u64 cpuid;
	struct latinfo lati, *latp;

	cpuid = bpf_get_smp_processor_id();
	latp = bpf_map_lookup_elem(&info_map, &cpuid);
	if (latp) {
		latp->last_seen_need_resched_ns = 0;
	} else {
		__builtin_memset(&lati, 0, sizeof(struct latinfo));
		lati.last_seen_need_resched_ns = 0;
		lati.ticks_without_resched = 0;
		bpf_map_update_elem(&info_map, &cpuid, &lati, BPF_ANY);
	}

	return 0;
}
