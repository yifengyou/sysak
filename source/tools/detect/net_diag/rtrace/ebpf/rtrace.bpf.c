#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.bpf.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

// from linux/icmp.h
#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH 4   /* Source Quench		*/
#define ICMP_REDIRECT 5        /* Redirect (change route)	*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIME_EXCEEDED 11  /* Time Exceeded		*/
#define ICMP_PARAMETERPROB 12  /* Parameter Problem		*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/
#define NR_ICMP_TYPES 18

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH 0  /* Network Unreachable		*/
#define ICMP_HOST_UNREACH 1 /* Host Unreachable		*/
#define ICMP_PROT_UNREACH 2 /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH 3 /* Port Unreachable		*/
#define ICMP_FRAG_NEEDED 4  /* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED 5    /* Source Route failed		*/
#define ICMP_NET_UNKNOWN 6
#define ICMP_HOST_UNKNOWN 7
#define ICMP_HOST_ISOLATED 8
#define ICMP_NET_ANO 9
#define ICMP_HOST_ANO 10
#define ICMP_NET_UNR_TOS 11
#define ICMP_HOST_UNR_TOS 12
#define ICMP_PKT_FILTERED 13   /* Packet filtered */
#define ICMP_PREC_VIOLATION 14 /* Precedence violation */
#define ICMP_PREC_CUTOFF 15    /* Precedence cut off */
#define NR_ICMP_UNREACH 15     /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET 0     /* Redirect Net			*/
#define ICMP_REDIR_HOST 1    /* Redirect Host		*/
#define ICMP_REDIR_NETTOS 2  /* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS 3 /* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL 0      /* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME 1 /* Fragment Reass time exceeded	*/

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, struct filter_map_key);
} filter_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct addr_pair);
    __type(value, struct sock *);
} flow_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, struct tid_map_key);
    __type(value, ENUM_TO_STRUCT(BASIC_INFO));
} tid_map SEC(".maps");

/**
 * @brief save data into buffer
 *
 * @param cd
 * @param ptr
 * @param size
 * @return __always_inline
 */
static __always_inline void buffer_input(struct cache_data *cd, void *ptr, uint32_t size)
{
    if (size == 0)
        return;

    if (cd->buffer->offset < MAX_BUFFER_SIZE - size)
    {
        bpf_probe_read(&(cd->buffer->buffer[cd->buffer->offset]), size, ptr);
        cd->buffer->offset += size;
    }
}

/**
 * @brief output buffer to userspace
 *
 * @param cd
 * @return __always_inline
 */
static __always_inline void buffer_output(struct cache_data *cd)
{
    int size = cd->buffer->offset & (MAX_BUFFER_SIZE - 1);
    bpf_perf_event_output(cd->ctx, &perf, BPF_F_CURRENT_CPU, cd->buffer->buffer, size);
    cd->buffer->offset = 0;
}

/**
 * @brief Compares two addresses for equality
 *
 * @param skb_ap
 * @param sk_ap
 * @return int
 */
static int addr_pair_cmp(struct addr_pair *skb_ap, struct addr_pair *sk_ap)
{
    if (sk_ap->dport == skb_ap->dport && sk_ap->sport == skb_ap->sport)
        return 0;

    return -1;
}

/**
 * @brief Set the seq object
 *
 * @param cd
 * @param seq
 * @param end_seq
 * @param rseq
 * @param rend_seq
 * @return __always_inline
 */
static __always_inline void set_seq(struct cache_data *cd, uint32_t *seq, uint32_t *end_seq, uint32_t *rseq, uint32_t *rend_seq)
{
    char *data;
    uint32_t len, tmp_seq, tmp_end_seq, tmp_rseq, tmp_rend_seq;
    struct tcp_skb_cb *tsc;
    uint32_t protocol = cd->sk_protocol & 0xff;
    if (protocol == IPPROTO_ICMP)
    {
        struct icmphdr *ih = ((struct icmphdr *)(&cd->th));
        uint16_t sequence;
        uint8_t type = ih->type;
        sequence = ih->un.echo.sequence;
        *seq = sequence;
        *end_seq = sequence + 1;
        *rseq = sequence;
        *rend_seq = sequence + 1;
        return;
    }

    if (cd->transport_header != (uint16_t)~0)
    {
        struct sk_buff *skb = cd->skb;
        BPF_CORE_READ_INTO(&data, skb, data);
        BPF_CORE_READ_INTO(&len, skb, len);

        if (cd->send)
        {
            *seq = bpf_ntohl(cd->th.seq);
            *end_seq = *seq + len - cd->transport_header + (data - cd->head) - cd->th.doff * 4;
            *rend_seq = bpf_ntohl(cd->th.ack_seq);
        }
        else
        {
            *rseq = bpf_ntohl(cd->th.seq);
            *rend_seq = *rseq + len - cd->transport_header + (data - cd->head) - cd->th.doff * 4;
            struct tcp_sock *ts = (struct tcp_sock *)cd->sk;
            BPF_CORE_READ_INTO(seq, ts, snd_una);
            *end_seq = bpf_ntohl(cd->th.ack_seq);
        }
    }
    else
    {
        tsc = (struct tcp_skb_cb *)((unsigned long)cd->skb + offsetof(struct sk_buff, cb[0]));
#define TCPHDR_ACK 0x10
        if (cd->send)
        {
            uint8_t tcp_flags;
            BPF_CORE_READ_INTO(&tcp_flags, tsc, tcp_flags);
            BPF_CORE_READ_INTO(seq, tsc, seq);
            BPF_CORE_READ_INTO(end_seq, tsc, end_seq);
            if (tcp_flags & TCPHDR_ACK)
            {
                BPF_CORE_READ_INTO(rend_seq, tsc, ack_seq);
            }
        }
        else
        {
            uint8_t tcp_flags;
            BPF_CORE_READ_INTO(&tcp_flags, tsc, tcp_flags);
            BPF_CORE_READ_INTO(rseq, tsc, seq);
            BPF_CORE_READ_INTO(rend_seq, tsc, end_seq);
            if (tcp_flags & TCPHDR_ACK)
            {
                struct tcp_sock *ts = (struct tcp_sock *)cd->sk;
                BPF_CORE_READ_INTO(seq, ts, snd_una);
                BPF_CORE_READ_INTO(end_seq, tsc, ack_seq);
            }
        }
    }
}

/**
 * @brief Set the seq by tsc object. Some functions may not have tcp headers,
 * such as __tcp_transmit_skb, so seq needs to be obtained from tcp_skb_cb.
 *
 * @param skb
 * @param seq
 * @param end_seq
 */
static void set_seq_by_tsc(struct sk_buff *skb, uint32_t *seq, uint32_t *end_seq)
{
    struct tcp_skb_cb *tsc;
    tsc = (struct tcp_skb_cb *)((unsigned long)skb + offsetof(struct sk_buff, cb[0]));
    BPF_CORE_READ_INTO(seq, tsc, seq);
    BPF_CORE_READ_INTO(end_seq, tsc, end_seq);
}

/**
 * @brief Set the addr pair by hdr object
 *
 * @param cd cache_data structure pointer
 * @param ap addr_pair structure pointer
 */
static void set_addr_pair_by_hdr(struct cache_data *cd, struct addr_pair *ap)
{
    ap->saddr = cd->ih.saddr;
    ap->daddr = cd->ih.daddr;

    switch (cd->sk_protocol)
    {
    case IPPROTO_ICMP:
        ap->sport = 0;
        ap->dport = 0;
        break;
    case IPPROTO_TCP:
        ap->sport = bpf_ntohs(cd->th.source);
        ap->dport = bpf_ntohs(cd->th.dest);
        break;
    default:
        break;
    }
}

/**
 * @brief Set the addr pair by sock object
 *
 * @param sk sock object pointer
 * @param ap addr_pair object pointer
 */
static __always_inline void set_addr_pair_by_sock(struct sock *sk, struct addr_pair *ap)
{
    BPF_CORE_READ_INTO(&ap->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&ap->dport, sk, __sk_common.skc_dport);
    ap->dport = bpf_ntohs(ap->dport);
    BPF_CORE_READ_INTO(&ap->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&ap->sport, sk, __sk_common.skc_num);
}

/**
 * @brief Bind sock and addr_pair, and update the sk pointer
 *
 * @param skp sock's secondary pointer
 * @param ap
 * @return int
 */
static int set_sock(struct sock **skp, struct addr_pair *ap)
{
    struct sock **skp_tmp;
    skp_tmp = bpf_map_lookup_elem(&flow_map, ap);

    // not found.
    if (!skp_tmp)
    {
        if (*skp)
        {
            bpf_map_update_elem(&flow_map, ap, skp, BPF_ANY);
            return 0;
        }
        return -1;
    }

    if (!*skp)
    {
        if (*skp_tmp == (struct sock *)FLOW_MAP_DEFAULT_VAL)
            return -1;
        // assign sock pointer.
        *skp = *skp_tmp;
    }
    else if (*skp != *skp_tmp)
        bpf_map_update_elem(&flow_map, ap, skp, BPF_ANY);
    return 0;
}

/**
 * @brief Set the cache data object
 *
 * @param cd cache_data structure pointer
 * @param skb sk_buff structure pointer
 * @return void
 */
static __always_inline void set_cache_data(struct cache_data *cd, struct sk_buff *skb)
{
    char *head, *l3_header_addr, *l4_header_addr = NULL;
    u16 mac_header, network_header, transport_header, size;
    uint32_t protocol;

    BPF_CORE_READ_INTO(&transport_header, skb, transport_header);
    BPF_CORE_READ_INTO(&head, skb, head);
    cd->transport_header = transport_header;

    BPF_CORE_READ_INTO(&network_header, skb, network_header);
    cd->network_header = network_header;
    if (network_header == 0)
    {
        BPF_CORE_READ_INTO(&mac_header, skb, mac_header);
        network_header = mac_header + MAC_HEADER_SIZE;
    }
    l3_header_addr = head + network_header;
    bpf_probe_read(&cd->ih, sizeof(struct iphdr), l3_header_addr);
    if (transport_header == (u16)~0)
        l4_header_addr = l3_header_addr + cd->ih.ihl * 4;
    else
        l4_header_addr = head + transport_header;

    if (!l4_header_addr)
        return;

    protocol = cd->sk_protocol == 0 ? cd->ih.protocol : cd->sk_protocol;
    cd->head = head;
    switch (protocol)
    {
    case IPPROTO_ICMP:
        size = sizeof(struct icmphdr);
        break;
    case IPPROTO_TCP:
        size = sizeof(struct tcphdr);
        break;
    default:
        size = 0;
        break;
    }
    if (size)
        bpf_probe_read(&cd->th, size, l4_header_addr);
    cd->sk_protocol = protocol;
    // BPF_CORE_READ_INTO(&head, cd, skb); // to generate cache_data btf info.
}

/**
 * @brief Filter out unwanted packets
 *
 * @param protocol
 * @param pid
 * @param ap
 * @return __always_inline
 */
static __always_inline int builtin_filter(uint32_t protocol, int pid, struct addr_pair *ap)
{
    u32 key = FILTER_MAP_DEFAULT_KEY;
    struct filter_map_key *fmkp;
    struct filter_meta *fm;
    struct addr_pair *app;
    int i, cnt;

    fmkp = bpf_map_lookup_elem(&filter_map, &key);
    if (!fmkp)
        return -1;

    // compare major protocol
    if ((fmkp->protocol & 0xff) != (protocol & 0xff))
        return -1;

    // compare minor protocol
    i = (fmkp->protocol >> 8) & 0xff;
    if (i && i != ((protocol >> 8) & 0xff))
        return -1;

#pragma unroll
    for (i = 0; i < FILTER_RULES_MAX_NUM; i++)
    {
        fm = &fmkp->fm[i];
        app = &fm->ap;

        if (ZERO_OR_EQUAL(fm->pid, pid) &&
            ZERO_OR_EQUAL(app->daddr, ap->daddr) &&
            ZERO_OR_EQUAL(app->dport, ap->dport) &&
            ZERO_OR_EQUAL(app->saddr, ap->saddr) &&
            ZERO_OR_EQUAL(app->sport, ap->sport))
            break;
    }

    if (i && i >= fmkp->cnt)
        return -1;
    return 0;
}

/**
 * @brief Main processing function entry
 *
 * @param ctx
 * @param sk
 * @param skb
 * @return __always_inline
 */
static __always_inline int do_trace_sk_skb(void *ctx, struct sock *sk, struct sk_buff *skb)
{
    INSTERT_PLACEHOLDER(rtrace_mask_t, 1);
    struct addr_pair skb_ap = {0};
    struct addr_pair sk_ap = {0};
    struct cache_data cd = {0};
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid;
    uint32_t default_buffer_map_key = 0;

    if (!sk)
        BPF_CORE_READ_INTO(&sk, skb, sk);

    cd.sk_protocol = 0;
    if (sk)
        cd.sk_protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);

    set_cache_data(&cd, skb);
    switch (cd.sk_protocol)
    {
    case IPPROTO_TCP:
        set_addr_pair_by_hdr(&cd, &skb_ap);
        if (sk)
        {
            // 1. May be the sending path
            // 2. May be the upper layer of the protocol stack
            set_addr_pair_by_sock(sk, &sk_ap);
            set_sock(&sk, &sk_ap);
            // todo: Consider the impact of nat
            if (addr_pair_cmp(&skb_ap, &sk_ap) == 0)
                cd.send = 1;
        }
        else
        {
            // may be the receive path
            sk_ap.daddr = skb_ap.saddr;
            sk_ap.dport = skb_ap.sport;
            sk_ap.saddr = skb_ap.daddr;
            sk_ap.sport = skb_ap.dport;
            set_sock(&sk, &sk_ap);
        }
        if (cd.th.syn)
            cd.sk_protocol |= (1 << 8);
        break;
    case IPPROTO_ICMP:
        sk_ap.sport = ((struct icmphdr *)&cd.th)->un.echo.id;
        sk_ap.dport = sk_ap.sport;
        set_sock(&sk, &sk_ap);
        break;
    default:
        return 0;
    }

    if (!sk)
        return -1;
    if (builtin_filter(cd.sk_protocol, pid, &sk_ap) < 0)
        return -1;

    // Here, we have captured the message we want.
    cd.skb = skb;
    cd.sk = sk;
    cd.ctx = ctx;
    cd.buffer = bpf_map_lookup_elem(&buffer_map, &default_buffer_map_key);

    if (!cd.buffer)
        return -1;

    if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), BASIC_INFO))
    {
        DECLARE_AND_INIT_STRUCT(BASIC_INFO, bi);
        set_seq(&cd, &bi.seq, &bi.end_seq, &bi.rseq, &bi.rend_seq);
        bi.mask = LOOKUP_PLACEHOLDER(1);
        bi.mask &= (~(1ull << KRETPROBE));
        bi.mask &= (~(1ull << LINEPROBE));
        bi.ip = PT_REGS_IP((struct pt_regs *)cd.ctx);
        bi.ts = bpf_ktime_get_ns();
        bi.ap = sk_ap;
        bi.pi.pid = pid;
        bpf_get_current_comm(bi.pi.comm, TASK_COMM_LEN);
        buffer_input(&cd, &bi, sizeof(bi));

        if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), KRETPROBE) || TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), LINEPROBE))
        {
            struct tid_map_key tmk = {0};
            tmk.tid = tid;
            // todo: lineprobe and multi-level Kretprobe nesting
            // tmk.bp = ((struct pt_regs *)cd.ctx)->bp;
            tmk.bp = 0;
            bi.mask = LOOKUP_PLACEHOLDER(1);
            bpf_map_update_elem(&tid_map, &tmk, &bi, BPF_ANY);
        }
    }

    if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), CGROUP))
    {
        DECLARE_AND_INIT_STRUCT(CGROUP, cg);
        read_ns_inum_by_sk(sk, &cg.inum);
        read_cgroup_id(&cg.cgroupid);
        buffer_input(&cd, &cg, sizeof(cg));
    }

    if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), STACK))
    {
        int size = sizeof(ENUM_TO_STRUCT(STACK));
        if (cd.buffer->offset < (MAX_BUFFER_SIZE - size))
        {
            bpf_get_stack(ctx, &(cd.buffer->buffer[cd.buffer->offset]), size, BPF_ANY);
            cd.buffer->offset += size;
        }
    }

    void *ctxp;
    asm volatile("%0 = %1"
                 : "=r"(ctxp)
                 : "r"(&cd));
    buffer_output(&cd);
    return 0;
}

SEC("kretprobe/common")
int kretprobe_common(struct pt_regs *ctx)
{
    struct tid_map_key tmk = {0};
    uint64_t mask;
    tmk.tid = (uint32_t)bpf_get_current_pid_tgid();
    tmk.bp = 0;
    ENUM_TO_STRUCT(BASIC_INFO) *bi = bpf_map_lookup_elem(&tid_map, &tmk);
    if (!bi)
        return 0;
    mask = bi->mask;
    if (TEST_NBITS_SET(mask, KRETPROBE))
    {
        bi->mask = 1ull << KRETPROBE;
        // bi->ip = ctx->ip; // cannot cover ip. rip now pointer to kretprobe_trampoline.
        bi->ts = bpf_ktime_get_ns();
        bi->ret = PT_REGS_RC(ctx);
        bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, bi, sizeof(ENUM_TO_STRUCT(BASIC_INFO)));
    }
    bpf_map_delete_elem(&tid_map, &tmk);
    return 0;
}

SEC("kprobe/lines")
int kprobe_lines(struct pt_regs *ctx)
{
    struct tid_map_key tmk = {0};
    uint64_t bp;
    // todo: find upper function rbp
    // bpf_probe_read_kernel(&bp, sizeof(bp), (void *)(ctx->bp))
    tmk.tid = (uint32_t)bpf_get_current_pid_tgid();
    tmk.bp = 0;
    ENUM_TO_STRUCT(BASIC_INFO) *bi = bpf_map_lookup_elem(&tid_map, &tmk);
    if (!bi)
        return 0;

    bi->mask = 1ull << LINEPROBE;
    bi->ip = ctx->ip;
    bi->ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, bi, sizeof(ENUM_TO_STRUCT(BASIC_INFO)));
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
    ENUM_TO_STRUCT(BASIC_INFO)
    bi = {0};
    INSTERT_PLACEHOLDER(rtrace_mask_t, 1);
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    uint32_t copied_seq;
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid;

    set_addr_pair_by_sock(sk, &bi.ap);
    set_sock(&sk, &bi.ap);

    if (builtin_filter(IPPROTO_TCP, pid, &bi.ap) < 0)
        return -1;

    bi.mask = 1 << BASIC_INFO;
    bi.ip = ctx->ip;
    bi.ts = bpf_ktime_get_ns();
    bi.seq = 0;
    bi.end_seq = 0;
    BPF_CORE_READ_INTO(&copied_seq, ts, copied_seq);
    bi.rseq = copied_seq - copied;
    bi.rend_seq = copied_seq;
    bi.pi.pid = pid;
    bpf_get_current_comm(bi.pi.comm, TASK_COMM_LEN);
    if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), KRETPROBE))
    {
        struct tid_map_key tmk = {0};
        tmk.tid = tid;
        tmk.bp = ctx->bp;
        bpf_map_update_elem(&tid_map, &tmk, &bi, BPF_ANY);
    }
    bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, &bi, sizeof(ENUM_TO_STRUCT(BASIC_INFO)));
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    ENUM_TO_STRUCT(BASIC_INFO)
    bi = {0};
    INSTERT_PLACEHOLDER(rtrace_mask_t, 1);
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid;

    set_addr_pair_by_sock(sk, &bi.ap);
    set_sock(&sk, &bi.ap);
    if (builtin_filter(IPPROTO_TCP, pid, &bi.ap) < 0)
        return -1;

    bi.mask = 1 << BASIC_INFO;
    bi.ip = ctx->ip;
    bi.ts = bpf_ktime_get_ns();
    BPF_CORE_READ_INTO(&bi.seq, ts, write_seq);
    bi.end_seq = bi.seq + size;
    bi.pi.pid = pid;
    bpf_get_current_comm(bi.pi.comm, TASK_COMM_LEN);
    if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), KRETPROBE))
    {
        struct tid_map_key tmk = {0};
        tmk.tid = tid;
        tmk.bp = ctx->bp;
        bpf_map_update_elem(&tid_map, &tmk, &bi, BPF_ANY);
    }
    bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, &bi, sizeof(ENUM_TO_STRUCT(BASIC_INFO)));
    return 0;
}

SEC("kprobe/raw_sendmsg")
int BPF_KPROBE(raw_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    ENUM_TO_STRUCT(BASIC_INFO)
    bi = {0};
    INSTERT_PLACEHOLDER(rtrace_mask_t, 1);
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid;
    struct icmphdr ih;
    uint32_t protocol;
    char *ptr;

    protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
    if (protocol != IPPROTO_ICMP)
        return 0;

    BPF_CORE_READ_INTO(&ptr, msg, msg_iter.iov, iov_base);
    bpf_probe_read(&ih, sizeof(ih), ptr);
    bi.ap.sport = ih.un.echo.id;
    bi.ap.dport = bi.ap.sport;
    set_sock(&sk, &bi.ap);
    if (builtin_filter(IPPROTO_ICMP, pid, &bi.ap) < 0)
        return -1;

    bi.mask = 1 << BASIC_INFO;
    bi.ip = ctx->ip;
    bi.ts = bpf_ktime_get_ns();
    bi.seq = ih.un.echo.sequence;
    bi.end_seq = bi.seq + 1;
    bi.rseq = bi.seq;
    bi.rend_seq = bi.end_seq;
    bpf_get_current_comm(bi.pi.comm, TASK_COMM_LEN);
    if (TEST_NBITS_SET(LOOKUP_PLACEHOLDER(1), KRETPROBE))
    {
        struct tid_map_key tmk = {0};
        tmk.tid = tid;
        tmk.bp = ctx->bp;
        bpf_map_update_elem(&tid_map, &tmk, &bi, BPF_ANY);
    }
    bpf_perf_event_output(ctx, &perf, BPF_F_CURRENT_CPU, &bi, sizeof(ENUM_TO_STRUCT(BASIC_INFO)));
    return 0;
}

#define SK0_SKB_ARG_FN(pos)                                            \
    SEC("kprobe/sk0_skb" #pos)                                         \
    int kprobe_sk0_skb##pos(struct pt_regs *pt)                        \
    {                                                                  \
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##pos(pt); \
        do_trace_sk_skb(pt, NULL, skb);                                \
        return 0;                                                      \
    }

#define SK_SKB_ARG_FN(skpos, skbpos)                                      \
    SEC("kprobe/sk" #skpos "_skb" #skbpos)                                \
    int kprobe_sk##skpos##_skb##skbpos(struct pt_regs *pt)                \
    {                                                                     \
        struct sock *sk = (struct sock *)PT_REGS_PARM##skpos(pt);         \
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##skbpos(pt); \
        do_trace_sk_skb(pt, sk, skb);                                     \
        return 0;                                                         \
    }

SK0_SKB_ARG_FN(1)
SK0_SKB_ARG_FN(2)
SK0_SKB_ARG_FN(3)
SK0_SKB_ARG_FN(4)
SK0_SKB_ARG_FN(5)

SK_SKB_ARG_FN(1, 2)
SK_SKB_ARG_FN(2, 3)
SK_SKB_ARG_FN(3, 4)
SK_SKB_ARG_FN(4, 5)

char LICENSE[] SEC("license") = "GPL";