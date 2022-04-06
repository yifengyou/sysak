// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../irqoff.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, struct args);
} argmap SEC(".maps");

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

#define GETARG_FROM_ARRYMAP(map,argp,type,member)({	\
	type retval = 0;			\
	int i = 0;				\
	argp = bpf_map_lookup_elem(&map, &i);	\
	if (argp) {				\
		retval = _(argp->member);		\
	}					\
	retval;					\
	})

static u64 get_period(void)
{
	__u64 period;
	struct args *argp;

	period = GETARG_FROM_ARRYMAP(argmap, argp, __u64, period);

	return period;
}

static u64 get_thresh(void)
{
	__u64 thresh;
	struct args *argp;

	thresh = GETARG_FROM_ARRYMAP(argmap, argp, __u64, threshold);

	return thresh;
}

static void set_prev_counter(u64 new_cnt, u64 cpu)
{
	struct info *infop, infos;

	infop = bpf_map_lookup_elem(&info_map, &cpu);
	if (infop) {
		infop->prev_counter = new_cnt;
	} else {
		__builtin_memset(&infos, 0, sizeof(struct info));
		infos.prev_counter = new_cnt;
		bpf_map_update_elem(&info_map, &cpu, &infos, 0);
	}
}

static u64 get_prev_counter(u64 cpuid)
{
	struct info *infop;

	infop = bpf_map_lookup_elem(&info_map, &cpuid);
	if (infop) {
		return _(infop->prev_counter);
	} else {
		return 0;
	}
}

SEC("perf_event")
int on_irqoff_event(struct bpf_perf_event_data *ctx)
{
	int ret;
	struct event event = {};
	struct bpf_perf_event_value value_buf;
	char time_fmt[] = "Get Time Failed, ErrCode: %d\n";
	u32 cpu = bpf_get_smp_processor_id();

	ret = bpf_perf_prog_read_value(ctx, (void *)&value_buf, sizeof(struct bpf_perf_event_value));
	if (!ret) {
		u64 threshold, delta, period, prev_counter;

		prev_counter = get_prev_counter(cpu);
		threshold = get_thresh();
		period = get_period();
		delta = value_buf.counter - prev_counter;
		if ((prev_counter > 0) && (period > 0) &&
		    (delta > period) && (delta - period > threshold)) {
			event.cpu = cpu;
			event.delay = delta/1000;
			event.pid = bpf_get_current_pid_tgid();
			bpf_get_current_comm(&event.comm, sizeof(event.comm));
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
					      &event, sizeof(event));
		}
	} else {
		bpf_trace_printk(time_fmt, sizeof(time_fmt), ret);
	}

	set_prev_counter(value_buf.counter, cpu);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
