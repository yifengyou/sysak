#ifndef __RTRACE_UTILS_OBJECT_H
#define __RTRACE_UTILS_OBJECT_H

struct bpf_program *object_find_program(struct bpf_object *obj, int sk, int skb);

#endif