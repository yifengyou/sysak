#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <argp.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "memcg_usage.h"
#include "memcg_usage.skel.h"
#include "../cgtoollib.h"

const char *argp_program_version = "cgtrace usage 1.0";

static const char argp_program_doc[] =
    "\n Tracing memory usage for the memory cgroup\n"
    ;

static const struct argp_option usage_options[] = {
    {"timeout", 't', "time", 0, "time out"},
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

static struct memcg_usage_bpf *obj = NULL;
static struct memcg_mess* mess = NULL;

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

static int add_taskinfo(struct memcg_mess *m, struct memcg_usage usage)
{
    struct task_info *info_tmp = m->info;
    struct task_info *p = (struct task_info *)malloc(sizeof(struct task_info));
    if (p == NULL) {
	printf("malloc task info failed\n");
	return -ENOMEM;
    }

    p->pid = usage.ptid >> 32;
    p->tid = (unsigned int)usage.ptid;
    strncpy(p->comm, usage.comm, sizeof(p->comm) - 1);
    p->comm[sizeof(p->comm) - 1] = '\0';
    p->pgsize = usage.pgsize;
    p->next = NULL;

    if (info_tmp == NULL) {
	m->info = p;
    }
    else {
	while (info_tmp->next != NULL)
	    info_tmp = info_tmp->next;

	info_tmp->next = p;
    }

    m->task_num++;

    return 0;
}

static struct memcg_mess* mess_list_find(int key)
{
    struct memcg_mess *mess_tmp = mess;

    while (mess_tmp != NULL) {
	if (mess_tmp->knid == key)
	    return mess_tmp;

	mess_tmp = mess_tmp->next;
    }

    return NULL;
}

static int mess_list_insert(struct memcg_usage usage)
{
    int ret = 0;
    struct memcg_mess *mess_tmp;
    struct memcg_mess *m;

    m = (struct memcg_mess *)malloc(sizeof(struct memcg_mess));
    if (m == NULL) {
	printf("malloc mess failed\n");
	return -ENOMEM;
    }

    m->task_num = 0;
    m->info = NULL;
    m->knid = usage.knid;
    m->next = NULL;
    ret = add_taskinfo(m, usage);
    if (ret < 0)
	goto out_free;

    if (mess == NULL)
	mess = m;
    else {
	mess_tmp = mess;
	while (mess_tmp->next != NULL)
	    mess_tmp = mess_tmp->next;

	mess_tmp->next = m;
    }

    return ret;

out_free:
    free(m);
    return ret;
}

void mess_list_free()
{
    struct memcg_mess *mess_tmp;
    struct task_info *info_tmp;

    while (mess != NULL) {
	/* free task info of mess */
	while (mess->info != NULL) {
	    info_tmp = mess->info;
	    mess->info = mess->info->next;
	    free(info_tmp);
	}

	/* free mess */
	mess_tmp = mess;
	mess = mess->next;
	free(mess_tmp);
    }
}

static int usage_restore()
{
    int fd = bpf_map__fd(obj->maps.usage_hash_map);
    unsigned long key, next_key;
    struct memcg_usage usage;
    struct memcg_mess *m;
    int ret = 0;

    // calculate the number of tasks for each memcg
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &usage);

	m = mess_list_find(usage.knid);
	if (m == NULL) {
	    ret = mess_list_insert(usage);
	    if (ret < 0)
		return ret;
	}
	else {
	    ret = add_taskinfo(m, usage);
	    if (ret < 0)
		return ret;
	}

	key = next_key;
    }

    return ret;
}

static void free_map(void)
{
    int fd = bpf_map__fd(obj->maps.usage_hash_map);
    unsigned long key, next_key;

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
	bpf_map_delete_elem(fd, &next_key);
	key = next_key;
    }
}

static void usage_show(unsigned int knid)
{
    struct memcg_mess *mess_tmp = mess;
    struct task_info *info_tmp;
    char dir[PATH_MAX];
    bool find = false;

    while (mess_tmp != NULL) {
	if (knid == -1 || mess_tmp->knid == knid)
		find = true;
	else
		goto next;

	if (get_dir_by_knid(mess_tmp->knid, "memory", dir, sizeof(dir)) < 0) {
		printf("can't get cgroup dir by knid:%u\n", mess_tmp->knid);
		goto next;
	}

	printf("task number:%d cgroup dir:%s", mess_tmp->task_num, dir);
	printf(" PID    TID       COMM       PGSIZE\n");
	printf("-----------------------------------\n");

	/* list task info of mess */
	info_tmp = mess_tmp->info;
	while (info_tmp != NULL) {
	    printf("%-6u %-6u %-16s %u\n", info_tmp->pid, info_tmp->tid, info_tmp->comm, info_tmp->pgsize);
	    info_tmp = info_tmp->next;
	}
	printf("\n");
next:
	mess_tmp = mess_tmp->next;
    }

    if (find == false) {
	printf("can't get memory usage in %s. ", env.dir);
	printf("check whether the [dir] parameter is correct.\n");
    }
}

static void alarm_stop(int signo)
{
    unsigned int knid = -1;

    if (env.dir != NULL)
	knid = get_knid_by_dir(env.dir);

    if (usage_restore() == 0)
	usage_show(knid);

    free_map();
    mess_list_free();
}

int main(int argc, char **argv)
{
    int err;
    struct bpf_program *prog;
    static const struct argp argp = {
        .options = usage_options,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = NULL,
    };

    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print_fn);
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    obj = memcg_usage_bpf__open();
    if (!obj)
    {
        printf("failed to open BPF object\n");
        return 1;
    }

    bpf_object__for_each_program(prog, obj->obj) {
	if (!find_ksym_by_name(bpf_program__name(prog)))
	    bpf_program__set_autoload(prog, false);
    }

    err = memcg_usage_bpf__load(obj);
    if (err)
    {
        printf("failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    err = memcg_usage_bpf__attach(obj);
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
    memcg_usage_bpf__destroy(obj);
    return 0;
}
