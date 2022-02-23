// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../runqlen.h"
//#define MAX_CPU_NR	128
//#define MAX_SLOTS	32

//const volatile bool targ_per_cpu = false;

struct bpf_map_def SEC("maps") args_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(bool),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") hist_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct hist),
	.max_entries = MAX_CPU_NR,
};

#if 0
/* 
 * Todo: 
 * task->se.cfs_rq->nr_running is not the perfect soluthon for child cpu-cgroup
 */
static u64 get_runq_nr_run(struct task_struct *task)
{
	int limit;
	u64 nr_running = 0;
	struct sched_entity *se, *topse;

	limit = BPF_CORE_READ(task, se.depth);
	topse = BPF_CORE_READ(task, se.parent);
	if (topse) {
		for (se = topse; se && limit > 1; limit--) {
			topse = se;
			se = BPF_CORE_READ(se, parent);
		}
		nr_running = BPF_CORE_READ(topse, cfs_rq, nr_running);
	} else {
		nr_running = BPF_CORE_READ(task, se.cfs_rq, nr_running);
	}

	return nr_running;
}
#else
static u64 get_runq_nr_run(struct task_struct *task)
{
	u64 nr_running = BPF_CORE_READ(task, se.cfs_rq, nr_running);

	return nr_running;
}
#endif

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	struct task_struct *task;
	struct sched_entity *sep, *parent, *topse;
	struct hist hist, *histp;
	u64 slot, cpu = 0;
	bool *targ_per_cpu_p , targ_per_cpu = false;
	int arg_idx = 0;

	task = (void*)bpf_get_current_task();
	
	slot = get_runq_nr_run(task);
	/*
	 * Calculate run queue length by subtracting the currently running task,
	 * if present. len 0 == idle, len 1 == one running task.
	 */
	if (slot > 0)
		slot--;

	targ_per_cpu_p = bpf_map_lookup_elem(&args_map, &arg_idx);
	if (targ_per_cpu_p)
		targ_per_cpu = *targ_per_cpu_p;
	if (targ_per_cpu) {
		cpu = bpf_get_smp_processor_id();
		/*
		 * When the program is started, the user space will immediately
		 * exit when it detects this situation, here just to pass the
		 * verifier's check.
		 */
		if (cpu >= MAX_CPU_NR)
			return 0;
	}
	histp = bpf_map_lookup_elem(&hist_map, &cpu);
	if (histp) {
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		if (targ_per_cpu)
			histp->slots[slot]++;
		else
			__sync_fetch_and_add(&histp->slots[slot], 1);
		bpf_map_update_elem(&hist_map, &cpu, histp, BPF_ANY);
	} else
		return -1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
