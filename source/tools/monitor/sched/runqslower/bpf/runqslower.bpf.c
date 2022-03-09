// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../runqslower.h"

#define TASK_RUNNING	0
#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

struct args {
	__u64 min_us;
	pid_t targ_pid;
	pid_t targ_tgid;
};

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
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

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

/* record enqueue timestamp */
static __always_inline
int trace_enqueue(u32 tgid, u32 pid)
{
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
	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("tp/sched/sched_wakeup")
int handle__sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
	pid_t pid = 0;
	bpf_probe_read(&pid, sizeof(pid), &(ctx->pid));

	return trace_enqueue(0, pid);
}

SEC("tp/sched/sched_wakeup_new")
int handle__sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
	pid_t pid = 0;
	bpf_probe_read(&pid, sizeof(pid), &(ctx->pid));

	return trace_enqueue(0, pid);
}

SEC("tp/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
	int cpuid;
	u32 pid, prev_pid;
	long int prev_state;
	struct event event = {};
	u64 *tsp, delta_us, min_us;
	struct args *argp;

	prev_pid = ctx->prev_pid;
	pid = ctx->next_pid;
	prev_state = ctx->prev_state;
	cpuid = bpf_get_smp_processor_id();
	/* ivcsw: treat like an enqueue event and store timestamp */
	if (prev_state == TASK_RUNNING)
		trace_enqueue(0, prev_pid);


	/* fetch timestamp and calculate delta */
	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;   /* missed enqueue */

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	min_us = GETARG_FROM_ARRYMAP(argmap, argp, u64, min_us);
	if (min_us && delta_us <= min_us)
		return 0;

	event.cpuid = cpuid;
	event.pid = pid;
	event.prev_pid = prev_pid;
	event.delta_us = delta_us;
	bpf_probe_read(event.task, sizeof(event.task), &(ctx->next_comm));
	bpf_probe_read(event.prev_task, sizeof(event.prev_task), &(ctx->prev_comm));

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
