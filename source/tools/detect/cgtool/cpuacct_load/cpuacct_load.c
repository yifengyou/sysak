#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <argp.h>
#include <unistd.h>
#include <signal.h>
#include "cpuacct_load.h"
#include "cpuacct_load.skel.h"
#include "../cgtoollib.h"

const char *argp_program_version = "cgtrace cpuacct_load 1.0";
static const char argp_program_doc[] =
    "\n Tracing cpu load for the cpuacct cgroup\n"
    ;

static const struct argp_option cpuacct_load_options[] = {
    {"timeout", 't', "timeout", 0, "time out"},
    {"dir", 'f', "dir", 0, "cgroup dir"},
    {"btf", 'b', "BTF_PATH", 0, "Specify path of the custom btf"},
    {"debug", 'd', NULL, 0, "Enable libbpf debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static struct env
{
    int timeout;
    char *dir;
    bool debug;
    char *btf_custom_path;
} env = {
    .debug = false,
    .btf_custom_path = NULL,
};

static struct cpuacct_load_bpf *obj;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (!env.debug)
        return 0;
    return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{

    switch (key)
    {
    case 't':
        env.timeout = atoi(arg);
        break;
    case 'f':
        env.dir = arg;
        break;
    case 'd':
        env.debug = true;
        break;
    case 'b':
        env.btf_custom_path = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static void print_cpuacct_load(struct cpuacct_load_bpf *obj, unsigned int knid)
{
    int fd = bpf_map__fd(obj->maps.cpuacct_load_hash_map);
    int j, k, loop;
    unsigned long key, next_key;
    struct cpuacct_load load;
    bool find = false;
    char dir[PATH_MAX];

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
    {
        if ((bpf_map_lookup_elem(fd, &next_key, &load)) != 0) {
		goto next;
	}

	if (load.avenrun_n >= 10)
		k = load.avenrun_index;
	else
		k = 0;

	if (knid == -1 || load.knid == knid)
		find = true;
	else
		goto next;

	if (get_dir_by_knid(load.knid, "cpuacct", dir, sizeof(dir)) < 0) {
		printf("can't get cgroup dir by knid:%u\n", load.knid);
		goto next;
	}

	printf("cgroup dir:%s", dir);
	printf("times:\n");

	/* print avenrun */
	for (loop = 0; loop < 3; loop++) {
	    printf("avenrun%d:", loop);
	    j = k;
	    for (int i = 0; i < load.avenrun_n; i++) {
		printf(" %lu", load.run[j][loop]);
		j = (j + 1) % 10;
	    }
	    printf("\n");
	}

	/* print load */
	for (loop = 0; loop < 3; loop++) {
	    printf("load%d:", loop);
	    j = k;
	    for (int i = 0; i < load.avenrun_n; i++) {
		printf(" %lu.%02lu", cal_load_int(load.run[j][loop]), cal_load_frac(load.run[j][loop]));
		j = (j + 1) % 10;
	    }
	    printf("\n");
	}
	printf("\n");
next:
	bpf_map_delete_elem(fd, &next_key);
	key = next_key;
    }

    if (find == false) {
	printf("can't get load trace, maybe should do:\n");
	printf("1) echo 1 > /proc/async_load_calc\n");
	printf("2) echo 1 > cpuacct.enable_sli\n");
	printf("3) check whether the [dir] parameter is correct\n");
    }
}

static void alarm_stop(int signo)
{
    unsigned int knid = -1;

    if (env.dir != NULL)
	knid = get_knid_by_dir(env.dir);

    print_cpuacct_load(obj, knid);
}

int main(int argc, char **argv)
{
    int err;
    struct bpf_program *prog;
    static const struct argp argp = {
        .options = cpuacct_load_options,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = NULL,
    };

    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print_fn);
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    obj = cpuacct_load_bpf__open();
    if (!obj)
    {
        printf("failed to open BPF object\n");
        return 1;
    }

    bpf_object__for_each_program(prog, obj->obj) {
	if (!find_ksym_by_name(bpf_program__name(prog))) {
	    printf("not find %s in /proc/kallsyms, not support\n", bpf_program__section_name(prog));
	    return -ENOTSUP;
	}
    }

    err = cpuacct_load_bpf__load(obj);
    if (err)
    {
        printf("failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    err = cpuacct_load_bpf__attach(obj);
    if (err)
    {
        printf("failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }

    if (env.timeout == 0)
	env.timeout = -1;

    signal(SIGINT, alarm_stop);
    signal(SIGALRM, alarm_stop);

    alarm(env.timeout);
    sleep(env.timeout + 1);

cleanup:
    cpuacct_load_bpf__destroy(obj);
    return 0;
}
