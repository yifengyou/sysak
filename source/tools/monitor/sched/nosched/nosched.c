// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>	/* bpf_obj_pin */
#include <getopt.h>
#include "bpf/nosched.skel.h"
#include "nosched.comm.h"

#define MAX_SYMS 300000
unsigned int nr_cpus;
FILE *filep = NULL;
char filename[256] = {0};
char log_dir[] = "/var/log/sysak/nosched";
char defaultfile[] = "/var/log/sysak/nosched/nosched.log";

struct summary summary, *percpu_summary;
static struct ksym syms[MAX_SYMS];
static volatile sig_atomic_t exiting;
static int sym_cnt,  stackmp_fd;
char *help_str = "sysak nosched";
struct evn {
	__u64 thresh;
	bool summary;
} env = {
	.thresh = LAT_THRESH_NS,
	.summary = false,
};

static void usage(char *prog)
{
	const char *str =
	"  Usage: %s [OPTIONS]\n"
	"  Options:\n"
	"  -t THRESH_TIME       specify the threshold time(ms), default=10ms\n"
	"  -f result.log        result file, default is /var/log/sysak/nosched.log\n"
	"  -s TIME              specify how long to run \n"
	"  -S                   record the result as summary mod\n"
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
	return 0;
	//return vfprintf(stderr, format, args);
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
	fprintf(filep, "<0x%llx> %s\n", addr, sym->name);
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
		fprintf(filep, "<0x0000000000000000>:error=%d\n", (int)(ret));
	}
}

#define SEC_TO_NS	(1000*1000*1000)

static int prepare_dictory(char *path)
{
	int ret;

	ret = mkdir(path, 0777);
	if (ret < 0 && errno != EEXIST)
		return errno;
	else
		return 0;
}

static void update_summary(struct summary* summary, const struct event *e)
{
	int idx;

	summary->num++;
	idx = summary->num % CPU_ARRY_LEN;
	summary->total += e->delay;
	summary->cpus[idx] = e->cpu;
	if (summary->max.value < e->delay) {
		summary->max.value = e->delay;
		summary->max.cpu = e->cpu;
		summary->max.pid = e->pid;
		summary->max.stamp = e->stamp;
		strncpy(summary->max.comm, e->comm, 16);
	}
}

static int record_summary(struct summary *summary, long offset, bool total)
{
	char *p;
	int i, idx, pos;
	char buf[128] = {0};
	char header[16] = {0};

	snprintf(header, 15, "cpu%ld", offset);
	p = buf;
	pos = sprintf(p,"%-7s %-5lu %-6llu",
		total?"nosche":header,
		summary->num, summary->total/1000);

	if (total) {
		idx = summary->num % CPU_ARRY_LEN;
		for (i = 1; i <= CPU_ARRY_LEN; i++) {
			p = p+pos;
			pos = sprintf(p, " %d", summary->cpus[(idx+i)%CPU_ARRY_LEN]);
		}
	}

	p = p+pos;
	pos = sprintf(p, "   %-4llu %-12llu %-3d %-9d %-15s\n",
		summary->max.value/1000, summary->max.stamp/1000,
		summary->max.cpu, summary->max.pid, summary->max.comm);

	if (total)
		fseek(filep, 0, SEEK_SET);
	else
		fseek(filep, (offset)*(p-buf+pos), SEEK_CUR);

	fprintf(filep, "%s", buf);
	return 0;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[64];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%F_%H:%M:%S", tm);
	if (env.summary) {
		struct summary *sumi;

		if (e->cpu > nr_cpus - 1)
			return;

		sumi = &percpu_summary[e->cpu];
		update_summary(&summary, e);
		update_summary(sumi, e);
		if(record_summary(&summary, 0, true))
			return;
		record_summary(sumi, e->cpu, false);
	} else {
		fprintf(filep, "%-21s %-5d %-15s %-8d %-10llu\n",
			ts, e->cpu, e->comm, e->pid, e->delay);
		print_stack(stackmp_fd, e->ret);
	}
}

void nosched_handler(int poll_fd)
{
	int err = 0;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};

	if (!env.summary) {
		fprintf(filep, "%-21s %-5s %-15s %-8s %-10s\n",
			"TIME(nosched)", "CPU", "COMM", "TID", "LAT(us)");
	} else {
		int i;
		char buf[78] = {' '};
		fprintf(filep, "nosche\n");
		for (i = 0; i < nr_cpus; i++)
			fprintf(filep, "cpu%d  %s\n", i, buf);
		fseek(filep, 0, SEEK_SET);
	}
	pb_opts.sample_cb = handle_event;
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

static void sig_int(int signo)
{
	exiting = 1;
}

static void sig_alarm(int signo)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	struct nosched_bpf *skel;
	struct args args;
	int c, option_index, args_key;
	unsigned long span = 0;
	int err, map_fd0, map_fd1, map_fd2;

	err = prepare_dictory(log_dir);
	if (err)
		return err;

	for (;;) {
		c = getopt_long(argc, argv, "t:f:s:Sh", NULL, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 't':
				env.thresh = (int)strtoul(optarg, NULL, 10);
				if ((errno == ERANGE && (env.thresh == LONG_MAX || env.thresh == LONG_MIN))
					|| (errno != 0 && env.thresh == 0)) {
					fprintf(stderr, "%s :strtoul %s\n", strerror(errno), optarg);
					return errno;
				}
				env.thresh = env.thresh*1000*1000;
				break;
			case 'f':
				if (strlen(optarg) < 2)
					strncpy(filename, defaultfile, sizeof(filename));
				else 
					strncpy(filename, optarg, sizeof(filename));
				filep = fopen(filename, "w+");
				if (!filep) {
					int ret = errno;
					fprintf(stderr, "%s :fopen %s\n",
					strerror(errno), filename);
					return ret;
				}
				break;
			case 's':
				span = (int)strtoul(optarg, NULL, 10);
				if ((errno == ERANGE && (span == LONG_MAX || span == LONG_MIN))
					|| (errno != 0 && span == 0)) {
					perror("strtoul");
					return errno;
				}
				break;
			case 'S':
				nr_cpus = libbpf_num_possible_cpus();
				percpu_summary = malloc(nr_cpus*sizeof(struct summary));
				if (!percpu_summary)
					return -ENOMEM;
				env.summary = 1;
				break;
			case 'h':
				usage(help_str);
				break;
			default:
				usage(help_str);
		}
	}
	if (!filep) {
		filep = fopen(defaultfile, "w+");
		if (!filep) {
			int ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), defaultfile);
			return ret;
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
	map_fd1 = bpf_map__fd(skel->maps.events);
	map_fd2 = bpf_map__fd(skel->maps.stackmap);
	if (signal(SIGINT, sig_int) == SIG_ERR ||
		signal(SIGALRM, sig_alarm) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	stackmp_fd = map_fd2;
	args_key = 0;
	args.flag = TIF_NEED_RESCHED;
	args.thresh = env.thresh;
	err = bpf_map_update_elem(map_fd0, &args_key, &args, 0);
	if (err) {
		fprintf(stderr, "Failed to update flag map\n");
		goto cleanup;
	}

	if (span)
		alarm(span);

	nosched_handler(map_fd1);

cleanup:
	nosched_bpf__destroy(skel);
	return -err;
}
