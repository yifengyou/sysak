// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "irqoff.h"
#include "./bpf/irqoff.skel.h"

struct env {
	__u64 sample_period;
	time_t duration;
	bool verbose, summary;
	__u64 threshold;
} env = {
	.duration = 0,
	.threshold = 10,	/* 10ms */
	.summary = false,
};

static int nr_cpus;
FILE *filep = NULL;
char filename[256] = {0};
struct summary summary, *percpu_summary;
char log_dir[] = "/var/log/sysak/irqoff";
char defaultfile[] = "/var/log/sysak/irqoff/irqoff.log";

static struct ksym *ksyms;
static int stackmp_fd;
volatile sig_atomic_t exiting = 0;

void print_stack(int fd, __u32 ret, struct ksym *syms);
int load_kallsyms(struct ksym **pksyms);

const char *argp_program_version = "irqoff 0.1";
const char argp_program_doc[] =
"Catch the irq-off time more than threshold.\n"
"\n"
"USAGE: irqoff [--help] [-t THRESH(ms)] [-f LOGFILE] [duration(s)]\n"
"\n"
"EXAMPLES:\n"
"    irqoff                # run forever, and detect irqoff more than 10ms(default)\n"
"    irqoff -S 	  	   # record the result as summary mod\n"
"    irqoff -t 15          # detect irqoff with threshold 15ms (default 10ms)\n"
"    irqoff -f a.log       # record result to a.log (default to ~sysak/irqoff/irqoff.log)\n";

static const struct argp_option opts[] = {
	{ "threshold", 't', "THRESH", 0, "Threshold to detect, default 10ms"},
	{ "logfile", 'f', "LOGFILE", 0, "logfile for result"},
	{ "summary", 'S', NULL, 0, "Summary the output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int ret = errno;
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'S':
		percpu_summary = malloc(nr_cpus*sizeof(struct summary));
		if (!percpu_summary)
			return -ENOMEM;
		env.summary = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 't':
		errno = 0;
		__u64 thresh;
		thresh = strtoull(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid threshold\n");
			argp_usage(state);
			break;
		} else if (thresh < 5) {
			fprintf(stderr, "threshold must >5ms, set to default 10ms\n");
			break;
		}
		env.threshold = thresh * 1000*1000;
		break;
	case 'f':
		if (strlen(arg) < 2)
			strncpy(filename, defaultfile, sizeof(filename));
		else 
			strncpy(filename, arg, sizeof(filename));
		filep = fopen(filename, "w+");
		if (!filep) {
			ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), filename);
			return ret;
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno) {
			ret = errno;
			fprintf(stderr, "invalid duration\n");
			argp_usage(state);
			return ret;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	if (!filep) {
		filep = fopen(defaultfile, "w+");
		if (!filep) {
			ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), defaultfile);
			return ret;
		}
	}

	/* refer to watchdog.c:set_sample_period, sample_period set to thres*2/5. */
	env.sample_period = env.threshold*2/5;

	return 0;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int
open_and_attach_perf_event(struct perf_event_attr *attr,
			   struct bpf_program *prog,
			   struct bpf_link *links[])
{
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: %d\n", i);
			close(fd);
			return -1;
		}
	}
	return 0;
}

/* surprise! return 0 if failed! */
static int attach_prog_to_perf(struct irqoff_bpf *obj,
		struct bpf_link **sw_mlinks,struct bpf_link **hw_mlinks)
{
	int ret = 0;

	struct perf_event_attr attr_hw = {
		.type = PERF_TYPE_HARDWARE,
		.freq = 0,
		.sample_period = env.sample_period*2,	/* refer to watchdog_update_hrtimer_threshold() */
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};

	struct perf_event_attr attr_sw = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 0,
		.sample_period = env.sample_period,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	if (!open_and_attach_perf_event(&attr_hw, obj->progs.hw_irqoff_event, hw_mlinks)) {
		ret = 1<<PERF_TYPE_SOFTWARE;
		if (!open_and_attach_perf_event(&attr_sw, obj->progs.sw_irqoff_event1, sw_mlinks))
			ret = ret | 1<<PERF_TYPE_SOFTWARE;

	} else {
		if (!open_and_attach_perf_event(&attr_sw, obj->progs.sw_irqoff_event2, sw_mlinks))
			ret = 1<<PERF_TYPE_SOFTWARE;
	}
	return ret;
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
		total?"irqoff":header,
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
		print_stack(stackmp_fd, e->ret, ksyms);
	}
}

void irqoff_handler(int poll_fd, int map_fd)
{
	int arg_key = 0, err = 0;
	struct arg_info arg_info = {};
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};

	if (!env.summary) {
		fprintf(filep, "%-21s %-5s %-15s %-8s %-10s\n",
			"TIME(irqoff)", "CPU", "COMM", "TID", "LAT(us)");
	} else {
		int i;
		char buf[78] = {' '};
		fprintf(filep, "irqoff\n");
		for (i = 0; i < nr_cpus; i++)
			fprintf(filep, "cpu%d  %s\n", i, buf);
		fseek(filep, 0, SEEK_SET);
	}

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(poll_fd, 64, &pb_opts);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto clean_irqoff;
	}

	arg_info.thresh = env.threshold;
	err = bpf_map_update_elem(map_fd, &arg_key, &arg_info, 0);
	if (err) {
		fprintf(stderr, "Failed to update arg_map\n");
		goto clean_irqoff;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto clean_irqoff;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

clean_irqoff:
	perf_buffer__free(pb);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int prepare_dictory(char *path)
{
	int ret;

	ret = mkdir(path, 0777);
	if (ret < 0 && errno != EEXIST)
		return errno;
	else
		return 0;
}

static void sig_alarm(int signo)
{
	exiting = 1;
}

static void sig_int(int sig)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	int err, i, ent_fd, arg_fd;
	struct irqoff_bpf *obj;
	struct bpf_link **sw_mlinks, **hw_mlinks= NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = prepare_dictory(log_dir);
	if (err) {
		fprintf(stderr, "prepare_dictory %s fail\n", log_dir);
		return err;
	}
	ksyms = NULL;

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		fprintf(stderr, "argp_parse fail\n");
		return err;
	}
	libbpf_set_print(libbpf_print_fn);

	bump_memlock_rlimit();
	err = load_kallsyms(&ksyms);
	if (err) {
		fprintf(stderr, "Failed to load kallsyms\n");
		return err;
	}

	sw_mlinks = calloc(nr_cpus, sizeof(*sw_mlinks));
	if (!sw_mlinks) {
		fprintf(stderr, "failed to alloc sw_mlinks or rlinks\n");
		return 1;
	}
	hw_mlinks = calloc(nr_cpus, sizeof(*hw_mlinks));
	if (!hw_mlinks) {
		fprintf(stderr, "failed to alloc hw_mlinks or rlinks\n");
		free(sw_mlinks);
		return 1;
	}

	obj = irqoff_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		goto cleanup;
	}

	if (!attach_prog_to_perf(obj, sw_mlinks, hw_mlinks))
		goto cleanup;

	arg_fd = bpf_map__fd(obj->maps.arg_map);
	ent_fd = bpf_map__fd(obj->maps.events);
	stackmp_fd = bpf_map__fd(obj->maps.stackmap);

	if (signal(SIGINT, sig_int) == SIG_ERR ||
		signal(SIGALRM, sig_alarm) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.duration)
		alarm(env.duration);

	irqoff_handler(ent_fd, arg_fd);

cleanup:
	for (i = 0; i < nr_cpus; i++) {
		bpf_link__destroy(sw_mlinks[i]);
		bpf_link__destroy(hw_mlinks[i]);
	}
	free(sw_mlinks);
	free(hw_mlinks);
	if (ksyms)
		free(ksyms);
	irqoff_bpf__destroy(obj);

	return err != 0;
}

