#ifndef __RTRACE_RTRACE_H
#define __RTRACE_RTRACE_H

#define MAX_PROBE_NUM 1024

#include "common.usr.h"
#include "utils/btf.h"
#include "utils/disasm.h"
#include "utils/insn.h"
#include "utils/object.h"

struct dynamic_offsets
{
    int offs[10];
    int cnt;
    int arg;
    int size;
};

struct dynamic_fields
{
    char *ident;
    char* cast_name;
    int cast_type;
    int index;
    int pointer;
};

struct rtrace;

struct rtrace *rtrace_alloc_and_init(char *pin_path, char *btf_custom_path);
int rtrace_perf_map_fd(struct rtrace *r);
int rtrace_filter_map_fd(struct rtrace *r);
void rtrace_set_debug(bool debug);


// dynamic module.
int rtrace_dynamic_gen_offset(struct rtrace *r, struct dynamic_fields *df,
                              int df_cnt, int func_proto_id, struct dynamic_offsets *dos);
int rtrace_dynamic_gen_insns(struct rtrace *r, struct dynamic_offsets *dos, struct bpf_insn *insns, int cd_off);
struct btf *rtrace_dynamic_btf(struct rtrace *r);

// trace module.
int rtrace_trace_load_prog(struct rtrace *r, struct bpf_program *prog,
                           struct bpf_insn *insns, size_t insns_cnt);
struct bpf_program *rtrace_trace_program(struct rtrace *r, char *func, int sk, int skb);

#endif