#include <argp.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "schedmoni.h"

extern FILE *fp_rsw;
extern volatile sig_atomic_t exiting;
static int previous, th_ret;
extern struct env env;

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[64];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%F_%H:%M:%S", tm);
	if (env.previous)
		fprintf(fp_rsw, "%-21s %-5d %-15s %-8d %-10llu %-7d %-16s %-6d\n", ts, e->cpuid, e->task,
			e->pid, e->delta_us, e->rqlen, e->prev_task, e->prev_pid);
	else
		fprintf(fp_rsw, "%-21s %-5d %-15s %-8d %-10llu %-7d\n", ts, e->cpuid, e->task, e->pid,
			e->delta_us, e->rqlen);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

void *runslw_handler(void *arg)
{
	int i = 0, err = 0;
	struct args bpf_args;
	struct tharg *data = (struct tharg *)arg;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};

	previous = env.previous;
	if (env.previous)
		fprintf(fp_rsw, "%-21s %-5s %-15s %-8s %-10s %-7s %-16s %-6s\n", "TIME(runslw)", "CPU", "COMM", "TID", "LAT(us)", "RQLEN", "PREV COMM", "PREV TID");
	else
		fprintf(fp_rsw, "%-21s %-5s %-15s %-8s %-10s %-7s\n", "TIME(runslw)", "CPU", "COMM", "TID", "LAT(us)", "RQLEN");

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(data->fd, 128, &pb_opts);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto clean_runslw;
	}

	memset(&bpf_args, 0, sizeof(bpf_args));
	bpf_map_lookup_elem(data->ext_fd, &i, &bpf_args);
	bpf_args.ready = true;
	err = bpf_map_update_elem(data->ext_fd, &i, &bpf_args, 0);
	if (err) {
		fprintf(stderr, "Failed to update flag map\n");
		goto clean_runslw;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto clean_runslw;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

clean_runslw:
	perf_buffer__free(pb);
	th_ret = err;
	return &th_ret;
}
