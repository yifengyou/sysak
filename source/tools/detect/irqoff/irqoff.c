// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "irqoff.h"
#include "./bpf/irqoff.skel.h"

#define LAT_THRESH_NS	(10*1000*1000)

struct env {
	int sample_period;
	time_t duration;
	bool verbose;
} env = {
	.sample_period = 2*1000*1000 + 1,	//1ms
	.duration = 10,
};

__u64 threshold;
volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "irqoff 0.1";
const char argp_program_doc[] =
"Catch the irq-off time more than threshold.\n"
"\n"
"USAGE: irqoff [--help] [-c SAMPLE_PERIOD(ns)] [-t THRESH(ns)] [duration(s)]\n";

static const struct argp_option opts[] = {
	{ "sample_period", 'c', "SAMPLE_PERIOD", 0, "Period default to 2ms"},
	{ "threshold", 't', "THRESH", 0, "Threshold to detect, default 10ms"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'c':
		errno = 0;
		env.sample_period = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid sample period\n");
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		threshold = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid threshold\n");
			argp_usage(state);
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
			fprintf(stderr, "invalid duration\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
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

static int nr_cpus;

static int open_and_attach_perf_event(__u64 config, int period,
				struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 0,
		.sample_period = period,
		.config = config,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
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

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[64];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%F_%H:%M:%S", tm);
	fprintf(stdout, "%-21s %-5d %-15s %-8d %-10llu\n",
		ts, e->cpu, e->comm, e->pid, e->delay);
}

void irqoff_handler(int poll_fd)
{
	int err = 0;
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};

	fprintf(stdout, "%-21s %-5s %-15s %-8s %-10s\n", "TIME(irqoff)", "CPU", "COMM", "TID", "LAT(us)");

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(poll_fd, 64, &pb_opts);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
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
	int err, i, ent_fd, map_fd, args_key;
	struct args args;
	struct irqoff_bpf *obj;
	struct bpf_link **mlinks = NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	threshold = LAT_THRESH_NS;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	bump_memlock_rlimit();

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	mlinks = calloc(nr_cpus, sizeof(*mlinks));
	if (!mlinks) {
		fprintf(stderr, "failed to alloc mlinks or rlinks\n");
		return 1;
	}

	obj = irqoff_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		goto cleanup;
	}

	if (open_and_attach_perf_event(PERF_COUNT_SW_CPU_CLOCK,
					env.sample_period,
					obj->progs.on_irqoff_event, mlinks))
		goto cleanup;

	map_fd = bpf_map__fd(obj->maps.argmap);
	ent_fd = bpf_map__fd(obj->maps.events);

	args_key = 0;
	args.threshold = threshold;
	args.period = env.sample_period;
	err = bpf_map_update_elem(map_fd, &args_key, &args, 0);
	if (err) {
		fprintf(stderr, "Failed to update args map\n");
		goto cleanup;
	}
	printf("Running for %ld seconds thresh=%llu, or Hit Ctrl-C to end.\n", env.duration, threshold);

	if (signal(SIGINT, sig_int) == SIG_ERR ||
		signal(SIGALRM, sig_alarm) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	alarm(env.duration);
	irqoff_handler(ent_fd);

cleanup:
	for (i = 0; i < nr_cpus; i++) {
		bpf_link__destroy(mlinks[i]);
	}
	free(mlinks);
	irqoff_bpf__destroy(obj);

	return err != 0;
}
