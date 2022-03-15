// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "schedmoni.h"
#include "bpf/schedmoni.skel.h"

FILE *fp_nsc = NULL, *fp_rsw = NULL;
volatile sig_atomic_t exiting = 0;
char log_dir[] = "/var/log/sysak/schedmoni";
char rswf[] = "/var/log/sysak/schedmoni/runslow.log";
char nscf[] = "/var/log/sysak/schedmoni/nosched.log";
char filename[256] = {0};

struct env env = {
	.span = 0,
	.min_us = 10000,
	.fp = NULL,
};

const char *argp_program_version = "schedmoni 0.1";
const char argp_program_doc[] =
"Trace schedule latency.\n"
"\n"
"USAGE: schedmoni [--help] [-s SPAN] [-t TID] [-P] [min_us] [-f ./runslow.log]\n"
"\n"
"EXAMPLES:\n"
"    schedmoni          # trace latency higher than 10000 us (default)\n"
"    schedmoni -f a.log # trace latency and record result to a.log (default to /var/log/sysak/runslow.log)\n"
"    schedmoni 1000     # trace latency higher than 1000 us\n"
"    schedmoni -p 123   # trace pid 12dd3\n"
"    schedmoni -t 123   # trace tid 123 (use for threads only)\n"
"    schedmoni -s 10    # monitor for 10 seconds\n"
"    schedmoni -P       # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID to trace"},
	{ "tid", 't', "TID", 0, "Thread TID to trace"},
	{ "span", 's', "SPAN", 0, "How long to run"},
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID" },
	{ "logfile", 'f', "LOGFILE", 0, "logfile for result"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

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

static int prepare_dictory(char *path)
{
	int ret;

	ret = mkdir(path, 0777);
	if (ret < 0 && errno != EEXIST)
		return errno;
	else
		return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;
	static int pos_args;
	long long min_us, span;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		env.previous = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case 's':
		errno = 0;
		span = strtoul(arg, NULL, 10);
		if (errno || span <= 0) {
			fprintf(stderr, "Invalid SPAN: %s\n", arg);
			argp_usage(state);
		}
		env.span = span;
		break;
	case 'f':
		if (strlen(arg) < 2) {
			strncpy(filename, rswf, sizeof(filename));
			fp_rsw = fopen(filename, "a+");
			if (!fp_rsw) {
				int ret = errno;
				fprintf(stderr, "%s :fopen %s\n",
					strerror(errno), filename);
				return ret;
			}
			memset(filename, 0, sizeof(filename));
			strncpy(filename, nscf, sizeof(filename));
			fp_nsc = fopen(filename, "a+");
			if (!fp_nsc) {
				int ret = errno;
				fprintf(stderr, "%s :fopen %s\n",
					strerror(errno), filename);
				return ret;
			}
		} else {
			snprintf(filename, sizeof(filename), "%s.rswf", arg);
			fp_rsw = fopen(filename, "a+");
			if (!fp_rsw) {
				int ret = errno;
				fprintf(stderr, "%s :fopen %s\n",
					strerror(errno), filename);
				return ret;
			}
			memset(filename, 0, sizeof(filename));
			snprintf(filename, sizeof(filename), "%s.nscf", arg);
			fp_nsc = fopen(filename, "a+");
			if (!fp_nsc) {
				int ret = errno;
				fprintf(stderr, "%s :fopen %s\n",
					strerror(errno), filename);
				return ret;
			}
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			fprintf(stderr, "Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	if (!fp_rsw && !fp_nsc) {
		strncpy(filename, rswf, sizeof(filename));
		fp_rsw = fopen(filename, "a+");
		if (!fp_rsw) {
			int ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), filename);
			return ret;
		}
		memset(filename, 0, sizeof(filename));
		strncpy(filename, nscf, sizeof(filename));
		fp_nsc = fopen(filename, "a+");
		if (!fp_nsc) {
			int ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), filename);
			return ret;
		}
	}
	return 0;
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

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz);
void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt);
void *runslw_handler(void *arg);
void *runnsc_handler(void *arg);

int main(int argc, char **argv)
{
	void *res;
	int i, err, err1, err2;
	int arg_fd, ent_fd, stk_fd, stkext_fd;
	pthread_t pt_runslw, pt_runnsc;
	struct schedmoni_bpf *obj;
	struct args args = {};
	struct tharg runslw = {};
	struct tharg runnsc = {};
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = prepare_dictory(log_dir);
	if (err)
		return err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);
	
	bump_memlock_rlimit();
	
	obj = schedmoni_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = schedmoni_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = schedmoni_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	i = 0;
	arg_fd = bpf_map__fd(obj->maps.argmap);
	ent_fd = bpf_map__fd(obj->maps.events);
	stk_fd = bpf_map__fd(obj->maps.stackmap);
	stkext_fd = bpf_map__fd(obj->maps.stackmap_ext);
	args.targ_tgid = env.pid;
	args.targ_pid = env.tid;
	args.min_us = env.min_us;
	args.flag = TIF_NEED_RESCHED;

	err = bpf_map_update_elem(arg_fd, &i, &args, 0);
	if (err) {
		fprintf(stderr, "Failed to update flag map\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR ||
		signal(SIGALRM, sig_alarm) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	runslw.fd = ent_fd;
	err = pthread_create(&pt_runslw, NULL, runslw_handler, &runslw);
	if (err) {
		fprintf(stderr, "can't pthread_create runslw: %s\n", strerror(errno));
		goto cleanup;
	}
	runnsc.fd = stk_fd;
	runnsc.ext_fd = stkext_fd;

	err = pthread_create(&pt_runnsc, NULL, runnsc_handler, &runnsc);
	if (err) {
		fprintf(stderr, "can't pthread_create runnsc: %s\n", strerror(errno));
		goto cleanup;
	}

	if (env.span)
		alarm(env.span);

	err1 = pthread_join(pt_runslw, &res);
	err2 = pthread_join(pt_runnsc, &res);
	if (err1 || err2) {
		goto cleanup;
	}

cleanup:
	schedmoni_bpf__destroy(obj);

	return err != 0;
}
