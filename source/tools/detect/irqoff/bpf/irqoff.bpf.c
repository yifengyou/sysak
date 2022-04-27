// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../irqoff.h"

#define PERF_MAX_STACK_DEPTH	127
#define MAX_ENTRIES	10240
#define BPF_F_FAST_STACK_CMP	(1ULL << 9)
#define KERN_STACKID_FLAGS	(0 | BPF_F_FAST_STACK_CMP)

struct bpf_map_def SEC("maps") stackmap = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(u32),
	.value_size = PERF_MAX_STACK_DEPTH * sizeof(u64),
	.max_entries = 10000,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct arg_info);
} arg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct tm_info);
} tm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct info);
} info_map SEC(".maps");

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

static inline u64 get_thresh(void)
{
	u64 thresh, i = 0;
	struct arg_info *argp;

	argp = bpf_map_lookup_elem(&arg_map, &i);
	if (argp)
		thresh = argp->thresh;
	else
		thresh = -1;

	return thresh;
}

SEC("perf_event")
int hw_irqoff_event(struct bpf_perf_event_data *ctx)
{
	int i = 0;
	u64 now, delta, thresh, stamp;
	struct tm_info *tmifp;
	struct event event = {};
	u32 cpu = bpf_get_smp_processor_id();

	now = bpf_ktime_get_ns();
	tmifp = bpf_map_lookup_elem(&tm_map, &i);

	if (tmifp) {
		stamp = tmifp->last_stamp;
		thresh = get_thresh();
		if (stamp && (thresh != -1)) {
			delta = now - stamp;
			if (delta > thresh) {
				event.cpu = cpu;
				event.stamp = now;
				event.delay = delta/1000;
				event.pid = bpf_get_current_pid_tgid();
				bpf_get_current_comm(&event.comm, sizeof(event.comm));
				event.ret = bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
				bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
				      &event, sizeof(event));
			}
		}
	}

	return 0;
}

SEC("perf_event")
int sw_irqoff_event1(struct bpf_perf_event_data *ctx)
{
	int ret, i = 0;
	struct tm_info *tmifp, tm;

	tmifp = bpf_map_lookup_elem(&tm_map, &i);
	if (tmifp) {
		tmifp->last_stamp = bpf_ktime_get_ns();
	} else {
		__builtin_memset(&tm, 0, sizeof(tm));
		tm.last_stamp = bpf_ktime_get_ns();
		bpf_map_update_elem(&tm_map, &i, &tm, 0);
	}
	return 0;
}

SEC("perf_event")
int sw_irqoff_event2(struct bpf_perf_event_data *ctx)
{
	int i = 0;
	u64 now, delta, thresh, stamp;
	struct tm_info *tmifp, tm;
	struct event event = {};
	u32 cpu = bpf_get_smp_processor_id();

	now = bpf_ktime_get_ns();
	tmifp = bpf_map_lookup_elem(&tm_map, &i);

	if (tmifp) {
		stamp = tmifp->last_stamp;
		tmifp->last_stamp = now;
		thresh = get_thresh();
		if (stamp && (thresh != -1)) {
			delta = now - stamp;
			if (delta > thresh) {
				event.cpu = cpu;
				event.delay = delta/1000;
				event.pid = bpf_get_current_pid_tgid();
				bpf_get_current_comm(&event.comm, sizeof(event.comm));
				event.ret = bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
				bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
				      &event, sizeof(event));
			}
		}
	} else {
		__builtin_memset(&tm, 0, sizeof(tm));
		tm.last_stamp = now;
		bpf_map_update_elem(&tm_map, &i, &tm, 0);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
