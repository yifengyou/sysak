#ifndef _RTRACE_COMMON_BPF_H
#define _RTRACE_COMMON_BPF_H

#include "common.def.h"

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
} perf SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, uint32_t);
    __type(value, uint32_t);
} jmp_table SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct buffer);
} buffer_map SEC(".maps");

static __always_inline void set_pid_info(struct pid_info *pi)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;

    pi->pid = pid;
    bpf_get_current_comm(pi->comm, TASK_COMM_LEN);
}

union kernfs_node_id___419
{
    struct
    {
        u32 ino;
        u32 generation;
    };
    u64 id;
};

struct kernfs_node___419
{
    struct kernfs_node___419 *parent;
    union kernfs_node_id___419 id;
};

static __always_inline void read_cgroup_id(uint64_t *target_id)
{
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    struct kernfs_node *kn;
    BPF_CORE_READ_INTO(&kn, curr_task, cgroups, subsys[0], cgroup, kn);

    if (!kn)
        return;
    struct kernfs_node___419 *kn_old = (void *)kn;
    if (bpf_core_field_exists(kn_old->id))
        BPF_CORE_READ_INTO(target_id, kn_old, id.id);
    else
        BPF_CORE_READ_INTO(target_id, kn, id);
}

// for centos 3.10 kernel
struct net___310
{
    unsigned int proc_inum;
};

struct net_device___310
{
    struct net___310 *nd_net;
    int ifindex;
};

static __always_inline void read_ns_inum(struct sk_buff *skb, u32 *inum)
{
    struct net *net;
    if (bpf_core_field_exists(net->ns.inum))
    {
        struct net_device *dev;
        bpf_core_read(&dev, sizeof(dev), &skb->dev);
        bpf_core_read(&net, sizeof(net), &dev->nd_net.net);
        bpf_core_read(inum, sizeof(*inum), &net->ns.inum);
    }
    else
    {
        struct net___310 *net310;
        struct net_device___310 *dev310;
        bpf_core_read(&dev310, sizeof(dev310), &skb->dev);
        bpf_core_read(&net310, sizeof(net310), &dev310->nd_net);
        bpf_core_read(inum, sizeof(*inum), &net310->proc_inum);
    }
}

static __always_inline void read_ns_inum_by_sk(struct sock *sk, u32 *inum)
{
    struct net *net;
    if (bpf_core_field_exists(net->ns.inum))
        BPF_CORE_READ_INTO(inum, sk, __sk_common.skc_net.net, ns.inum);
    else
    {
        struct net___310 *net310;
        BPF_CORE_READ_INTO(&net310, sk, __sk_common.skc_net.net);
        BPF_CORE_READ_INTO(inum, net310, proc_inum);
    }
}

// 不依赖于sock或sk_buff，获取入参
static __always_inline void send_context(void *ctx, void *perf, uint8_t send)
{
    ENUM_TO_STRUCT(CONTEXT)
    ct = {0};
    ct.types = SET_MAJOR_TYPE(ct.types, MEMORY);
    ct.args[0] = (uint64_t)PT_REGS_PARM1((struct pt_regs *)ctx);
    ct.args[1] = (uint64_t)PT_REGS_PARM2((struct pt_regs *)ctx);
    ct.args[2] = (uint64_t)PT_REGS_PARM3((struct pt_regs *)ctx);
    ct.args[3] = (uint64_t)PT_REGS_PARM4((struct pt_regs *)ctx);
    ct.args[4] = (uint64_t)PT_REGS_PARM5((struct pt_regs *)ctx);
    bpf_perf_event_output(ctx, perf, BPF_F_CURRENT_CPU, &ct, sizeof(ENUM_TO_STRUCT(CONTEXT)));
}

static __always_inline void send_tcp_wind(void *ctx, void *perf, struct sock *sk, uint8_t send)
{
    ENUM_TO_STRUCT(TCP_WINDOW)
    tw = {0};
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    tw.types = SET_MAJOR_TYPE(tw.types, TCP_WINDOW);

    BPF_CORE_READ_INTO(&tw.rcv_nxt, ts, rcv_nxt);
    BPF_CORE_READ_INTO(&tw.rcv_wup, ts, rcv_wup);
    BPF_CORE_READ_INTO(&tw.snd_nxt, ts, snd_nxt);
    BPF_CORE_READ_INTO(&tw.snd_una, ts, snd_una);
    BPF_CORE_READ_INTO(&tw.copied_seq, ts, copied_seq);
    BPF_CORE_READ_INTO(&tw.snd_wnd, ts, snd_wnd);
    BPF_CORE_READ_INTO(&tw.rcv_wnd, ts, rcv_wnd);

    BPF_CORE_READ_INTO(&tw.lost_out, ts, lost_out);
    BPF_CORE_READ_INTO(&tw.packets_out, ts, packets_out);
    BPF_CORE_READ_INTO(&tw.retrans_out, ts, retrans_out);
    BPF_CORE_READ_INTO(&tw.sacked_out, ts, sacked_out);
    bpf_perf_event_output(ctx, perf, BPF_F_CURRENT_CPU, &tw, sizeof(ENUM_TO_STRUCT(TCP_WINDOW)));
}

static __always_inline void send_memory(void *ctx, void *perf, struct sock *sk, uint8_t send)
{
    ENUM_TO_STRUCT(MEMORY)
    mm = {0};
    atomic_long_t *map;
    mm.types = SET_MAJOR_TYPE(mm.types, MEMORY);
    BPF_CORE_READ_INTO(&map, sk, __sk_common.skc_prot, memory_allocated);
    bpf_probe_read(&mm.allocated, sizeof(atomic_long_t), map);
    BPF_CORE_READ_INTO(&mm.rmem_alloc, sk, sk_backlog.rmem_alloc.counter);
    BPF_CORE_READ_INTO(&mm.wmem_alloc, sk, sk_wmem_alloc);
    BPF_CORE_READ_INTO(&mm.forward_alloc, sk, sk_forward_alloc);
    BPF_CORE_READ_INTO(&mm.rcvbuf, sk, sk_rcvbuf);
    BPF_CORE_READ_INTO(&mm.sndbuf, sk, sk_sndbuf);
    bpf_perf_event_output(ctx, perf, BPF_F_CURRENT_CPU, &mm, sizeof(ENUM_TO_STRUCT(MEMORY)));
}

// Declare a map with key type uint64 according to enum type.
#define DECLARE_HASH_MAP(enum_type, entries)      \
    struct                                        \
    {                                             \
        __uint(type, BPF_MAP_TYPE_HASH);          \
        __uint(max_entries, entries);             \
        __type(key, u64);                         \
        __type(value, ENUM_TO_STRUCT(enum_type)); \
    } ENUM_TO_MAP_NAME(enum_type) SEC(".maps");

DECLARE_HASH_MAP(BASIC_INFO, MAX_ENTRIES)

#define UPDATE_HASH_MAP(enum_type, key, value) \
    bpf_map_update_elem(ENUM_TO_REF_MAP(enum_type), key, value, BPF_ANY);

#endif
