
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <bpf/btf.h>

#include "common.usr.h"
#include "utils/object.h"


struct bpf_program *object_find_program(struct bpf_object *obj, int sk, int skb)
{
    char func_name[FUNCNAME_MAX_LEN];
    sprintf(func_name, "kprobe_sk%d_skb%d", sk, skb);
    return bpf_object__find_program_by_name(obj, func_name);
}