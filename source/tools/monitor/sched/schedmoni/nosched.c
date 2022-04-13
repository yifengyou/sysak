// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "nosched.comm.h"
#include "schedmoni.h"

#define MAX_SYMS 300000
extern FILE *fp_nsc;
//extern char filename[256] = {0};

int stk_fd;
extern volatile sig_atomic_t exiting;
static struct ksym syms[MAX_SYMS];
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (!feof(f)) {
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;
		syms[i].addr = (long) addr;
		syms[i].name = strdup(func);
		i++;
	}
	fclose(f);
	sym_cnt = i;
	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
	return 0;
}

struct ksym *ksym_search(long key)
{
	int start = 0, end = sym_cnt;
	int result;

	/* kallsyms not loaded. return NULL */
	if (sym_cnt <= 0)
		return NULL;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &syms[mid];
	}

	if (start >= 1 && syms[start - 1].addr < key &&
	    key < syms[start].addr)
		/* valid ksym */
		return &syms[start - 1];

	/* out of range. return _stext */
	return &syms[0];
}

static void print_ksym(__u64 addr)
{
	struct ksym *sym;

	if (!addr)
		return;

	sym = ksym_search(addr);
	fprintf(fp_nsc, "<0x%llx> %s\n", addr, sym->name);
}

static void print_stack(int fd, __u32 ret)
{
	int i;
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};

	if (bpf_map_lookup_elem(fd, &ret, &ip) == 0) {
		for (i = 7; i < PERF_MAX_STACK_DEPTH - 1; i++)
			print_ksym(ip[i]);
	} else {
		if ((int)(ret) < 0)
		fprintf(fp_nsc, "<0x0000000000000000>:error=%d\n", (int)(ret));
	}
}

#define SEC_TO_NS	(1000*1000*1000)
static void stamp_to_date(__u64 stamp, char dt[], int len)
{
	time_t t, diff, last;
	struct tm *tm;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	time(&t);
	diff = ts.tv_sec*SEC_TO_NS + ts.tv_nsec - stamp;
	diff = diff/SEC_TO_NS;

	last = t - diff;
	tm = localtime(&last);
	strftime(dt, len, "%F_%H:%M:%S", tm);
}

void handle_event_nosch(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char ts[64];

	stamp_to_date(e->stamp, ts, sizeof(ts));
	fprintf(fp_nsc, "%-21s %-5d %-15s %-8d %-10llu\n",
		ts, e->cpuid, e->task, e->pid, e->delta_us);
	print_stack(stk_fd, e->ret);
}

void nosched_handler(int poll_fd)
{
	int err = 0;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};

	fprintf(fp_nsc, "%-21s %-5s %-15s %-8s %-10s\n",
		"TIME(nosched)", "CPU", "COMM", "TID", "LAT(us)");

	pb_opts.sample_cb = handle_event_nosch;
	pb = perf_buffer__new(poll_fd, 64, &pb_opts);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto clean_nosched;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto clean_nosched;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

clean_nosched:
	perf_buffer__free(pb);
}

void *runnsc_handler(void *arg)
{
	int err;
	struct tharg *runnsc = (struct tharg *)arg;
 
	err = load_kallsyms();
	if (err) {
		fprintf(stderr, "Failed to load kallsyms\n");
		return NULL;
	}

	nosched_handler(runnsc->ext_fd);

	return NULL;
}
