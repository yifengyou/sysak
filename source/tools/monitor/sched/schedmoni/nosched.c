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

static void print_stack(int fd, struct ext_key *key)
{
	int i;
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};

	if (bpf_map_lookup_elem(fd, &key->ret, &ip) == 0) {
		for (i = 7; i < PERF_MAX_STACK_DEPTH - 1; i++)
			print_ksym(ip[i]);
	} else {
		if ((int)(key->ret) < 0)
		fprintf(fp_nsc, "<0x0000000000000000>:error=%d\n", (int)(key->ret));
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

static void print_stacks(int fd, int ext_fd)
{
	char dt[64] = {0};
	struct ext_key ext_key = {}, next_key;
	struct ext_val value;

	fprintf(fp_nsc, "%-21s %-6s %-16s %-8s %-10s\n", "TIME(nosch)", "CPU", "COMM", "TID", "LAT(us)");
	while (bpf_map_get_next_key(ext_fd, &ext_key, &next_key) == 0) {
		bpf_map_lookup_elem(ext_fd, &next_key, &value);
		memset(dt, 0, sizeof(dt));
		stamp_to_date(value.stamp, dt, sizeof(dt));
		fprintf(fp_nsc, "%-21s %-6d %-16s %-8d %-10llu\n",
			dt, value.cpu, value.comm, value.pid, value.lat_us);
		print_stack(fd, &next_key);
		bpf_map_delete_elem(ext_fd, &next_key);
		ext_key = next_key;
	}
	printf("\n");
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

	while (!exiting) {
		sleep(1);
	}
	printf("\n");
	print_stacks(runnsc->fd, runnsc->ext_fd);

	return NULL;
}
