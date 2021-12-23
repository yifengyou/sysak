#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpftest.h"
#include "bpf/bpftest1.skel.h"
#include "bpf/bpftest2.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    // if (level == LIBBPF_DEBUG && !env.verbose)
    // 	return 0;
    return vfprintf(stderr, format, args);
}

#define LOAD_BPF_SKEL(name)                                                    \
    (                                                                          \
        {                                                                      \
            __label__ load_bpf_skel_out;                                       \
            int __ret = 0;                                                     \
            name = name##_bpf__open();                                         \
            if (!name)                                                         \
            {                                                                  \
                printf("failed to open BPF object\n");                         \
                __ret = -1;                                                    \
                goto load_bpf_skel_out;                                        \
            }                                                                  \
            __ret = name##_bpf__load(name);                                    \
            if (__ret)                                                         \
            {                                                                  \
                printf("failed to load BPF object: %d\n", err);                \
                goto load_bpf_skel_out;                                        \
            }                                                                  \
            __ret = name##_bpf__attach(name);                                  \
            if (__ret)                                                         \
            {                                                                  \
                printf("failed to attach BPF programs: %s\n", strerror(-err)); \
                goto load_bpf_skel_out;                                        \
            }                                                                  \
        load_bpf_skel_out:                                                     \
            __ret;                                                             \
        })

int main(int argc, char **argv)
{
    struct bpftest1_bpf *bpftest1 = NULL;
    struct bpftest2_bpf *bpftest2 = NULL;
    int err = 0;
    libbpf_set_print(libbpf_print_fn);

    err = LOAD_BPF_SKEL(bpftest1);
    if (err)
        goto cleanup;

    printf("bpftest1 program load done.\n");
    err = LOAD_BPF_SKEL(bpftest2);
    if (err)
        goto cleanup;

    printf("bpftest2 program load done, test finished. exit.\n");
    // while(1){}
cleanup:
    // destory the bpf program
    bpftest1_bpf__destroy(bpftest1);
    bpftest2_bpf__destroy(bpftest2);
    return 0;
}