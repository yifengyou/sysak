#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpftest.h"
#include "bpftest.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    // if (level == LIBBPF_DEBUG && !env.verbose)
    // 	return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct bpftest_bpf *obj;
    int err;
    libbpf_set_print(libbpf_print_fn);
    obj = bpftest_bpf__open();
    if (!obj)
    {
        printf("failed to open BPF object\n");
        return 1;
    }
    err = bpftest_bpf__load(obj);
    if (err)
    {
        printf("failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    err = bpftest_bpf__attach(obj);
    if (err)
    {
        printf("failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }
    printf("bpf program load done, test finished. exit.");
cleanup:
    // destory the bpf program
    bpftest_bpf__destroy(obj);
    return 0;
}