// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>	/* bpf_obj_pin */
#include <getopt.h>
#include "nosched.comm.h"
#include "bpf/nosched.skel.h"

#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];
static int sym_cnt;
char *help_str = "sysak nosched";

static void usage(char *prog)
{
	const char *str =
	"  Usage: %s [OPTIONS]\n"
	"  Options:\n"
	"  -t              specify the threshold time(ms), default=10ms\n"
	;

	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static void print_ksym(__u64 addr)
{
	struct ksym *sym;

	if (!addr)
		return;

	sym = ksym_search(addr);
	printf("<%llx> %s\n", addr, sym->name);
}

static void print_stack(int fd, struct ext_key *key)
{
	int i;
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};

	if (bpf_map_lookup_elem(fd, &key->ret, &ip) == 0) {
		for (i = 7; i < PERF_MAX_STACK_DEPTH; i++)
			print_ksym(ip[i]);
	} else {
		if ((int)(key->ret) < 0)
		printf("<0x0000000000000000>:error=%d\n", (int)(key->ret));
	}
}

static void print_stacks(int fd, int ext_fd)
{
	struct ext_key ext_key = {}, next_key;
	struct ext_val value;

	printf("***********************************\n");
	while (bpf_map_get_next_key(ext_fd, &ext_key, &next_key) == 0) {
		bpf_map_lookup_elem(ext_fd, &next_key, &value);
		printf("%s<%d> [%lld.%lld]: lat=%lldus, lat_tick=%d\n",
			 value.comm, value.pid, next_key.stamp/(1000000000),
			 next_key.stamp%(1000000000), value.lat_us,
			 value.nosched_ticks);
		print_stack(fd, &next_key);
		printf("----------------------\n");
		bpf_map_delete_elem(ext_fd, &next_key);
		ext_key = next_key;
	}
	printf("\n");
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char **argv)
{
	struct nosched_bpf *skel;
	struct args args;
	int c, option_index, args_key;
	unsigned long val;
	int err, map_fd0, /*map_fd1,*/ map_fd2, map_fd3;

	val = LAT_THRESH_NS;
	for (;;) {
		c = getopt_long(argc, argv, "t:h", NULL, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 't':
				val = (int)strtoul(optarg, NULL, 10);
				if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
					|| (errno != 0 && val == 0)) {
					perror("strtol");
					return errno;
				}
				printf("Threshold set to %ld ms\n", val);
				val = val*1000*1000;
				break;
			case 'h':
				usage(help_str);
				break;
			default:
				usage(help_str);
		}
	}
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();
	err = load_kallsyms();
	if (err) {
		fprintf(stderr, "Failed to load kallsyms\n");
		return err;
	}
	/* Open load and verify BPF application */
	skel = nosched_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = nosched_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}
	/* Attach tracepoint handler */
	err = nosched_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	map_fd0 = bpf_map__fd(skel->maps.args_map);
	/* map_fd1 = bpf_map__fd(skel->maps.info_map); */
	map_fd2 = bpf_map__fd(skel->maps.stackmap);
	map_fd3 = bpf_map__fd(skel->maps.stackmap_ext);
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	args_key = 0;
	args.flag = TIF_NEED_RESCHED;
	args.thresh = val;
	err = bpf_map_update_elem(map_fd0, &args_key, &args, 0);
	if (err) {
		fprintf(stderr, "Failed to update flag map\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	fprintf(stderr, "Running....\n tips:Ctl+c show the result!\n");
	while (!stop) {
		sleep(1);
	}
	printf("\n");
	print_stacks(map_fd2, map_fd3);
cleanup:
	nosched_bpf__destroy(skel);
	return -err;
}
