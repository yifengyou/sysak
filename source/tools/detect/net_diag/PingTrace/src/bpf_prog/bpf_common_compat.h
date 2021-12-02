#include "common_define.h"

static inline void pingtrace_map_value_clear(struct pingtrace_map_value *ptmv)
{
        int i;

        ptmv->softirq_ts = -1;
        #pragma unroll
        for(i = 0; i < PINGTRACE_MAP_ENTRY_NUM; ++i) {
                ptmv->entries[i].function_id = 0;
                ptmv->entries[i].ns = 0;
                ptmv->entries[i].ifindex = 0;
                ptmv->entries[i].net_inum = 0;
        }
}

static inline int update_map_with_new_entry(struct bpf_map_def *map, struct pingtrace_map_key *key, u32 function_id, u32 net_inum, u32 ifindex, u64 softirq_ts)
{
        struct pingtrace_map_value ptmv = {};

        pingtrace_map_value_clear(&ptmv);
        ptmv.entries[0].function_id = function_id;
        ptmv.entries[0].ns = bpf_ktime_get_ns();
        ptmv.entries[0].net_inum = net_inum;
        ptmv.entries[0].ifindex = ifindex;
        if (softirq_ts != -1)
                ptmv.softirq_ts = softirq_ts;
        return bpf_map_update_elem(map, key, &ptmv, BPF_ANY);
}

static inline int map_entry_slot_search(struct pingtrace_map_value *ptmv)
{
        int i;

        #pragma unroll
        for(i = 0; i < PINGTRACE_MAP_ENTRY_NUM; ++i)
                if (ptmv->entries[i].function_id == 0)  return i;
        return -1;
}

static inline void
update_map_with_exist_entry(struct pingtrace_map_value *ptmv, u32 function_id, u32 net_inum, u32 ifindex, u64 softirq_ts)
{
        int idx = 0;
        u64 ns;

        ns = bpf_ktime_get_ns();
        if (ptmv->entries[0].function_id &&
            (ptmv->entries[0].ns + PINGTRACE_MAX_RTT_NS) <= ns) {
                    pingtrace_map_value_clear(ptmv);
                    idx = 0;
                    goto ok;
        }

        idx = map_entry_slot_search(ptmv);
        if (idx == -1)  return;

ok:
        ptmv->entries[idx].function_id = function_id;
        ptmv->entries[idx].ns = ns;
        ptmv->entries[idx].net_inum = net_inum;
        ptmv->entries[idx].ifindex = ifindex;
        if (softirq_ts != -1)
                ptmv->softirq_ts = softirq_ts;
}

__attribute__((always_inline))
static inline int read_ns_inum(struct sk_buff *skb, u32 *inum, u32 *ifindex)
{
        struct net *net;
        struct net_device *dev;

        if (bpf_core_read(&dev, sizeof(dev), &skb->dev))
                return 1;
        if (bpf_core_read(&net, sizeof(net), &dev->nd_net.net))
                return 1;
        if (bpf_core_read(inum, sizeof(*inum), &net->ns.inum))
                return 1;
        if (bpf_core_read(ifindex, sizeof(*ifindex), &dev->ifindex))
                return 1;
        return 0;
}

__attribute__((always_inline))
static inline int
pt_packet_check_impl(struct sk_buff *skb, u8 *type, struct pingtrace_map_key *key, u32 *inum, u32 *ifindex, u32 expect_id)
{
        struct iphdr iph, *piph;
        struct bpf_icmp_header icmph, *picmph;
        u32 magic;
        u16 flag;
        u16 network_header;
        void* head;

        if (bpf_core_read(&network_header, sizeof(network_header), &skb->network_header))
                return 0;
        if (bpf_core_read(&head, sizeof(head), &skb->head))
                return 0;
        piph = (struct iphdr*)(head+network_header);

        if (bpf_probe_read(&iph, sizeof(iph), piph))
                return 0;
        if (iph.protocol != IPPROTO_ICMP)
                return 0;
        picmph = (struct bpf_icmp_header *)((void *)(piph) + iph.ihl*4);
        if (bpf_probe_read(&icmph, sizeof(icmph), picmph))
                return 0;
        if (icmph.type != ICMP_ECHO && icmph.type != ICMP_ECHOREPLY)
                return 0;
        if (icmph.code != PINGTRACE_CODE_MAGIC)
                return 0;
        if (ntohs(icmph.hdr.magic) != PINGTRACE_HDR_MAGIC)
                return 0;
        if (ntohs(icmph.hdr.flags) & PINGTRACE_F_DONTADD)
                return 0;
        if (read_ns_inum(skb, inum, ifindex))
                return 0;

        key->seq = ntohl(icmph.hdr.seq);
        key->id = ntohl(icmph.hdr.id);

        if (expect_id != (u32)(-1) && expect_id != key->id)
                return 0;

        *type = icmph.type;
        return 1;
}

__attribute__((always_inline))
static inline int
pt_packet_check(struct sk_buff *skb, u8 *type, struct pingtrace_map_key *key, u32 *inum, u32 *ifindex)
{
        return pt_packet_check_impl(skb, type, key, inum, ifindex, -1);
}

__attribute__((always_inline))
static inline int
pt_packet_check_with_id(struct sk_buff *skb, u8 *type, struct pingtrace_map_key *key, u32 *inum, u32 *ifindex, u32 expect_id)
{
        return pt_packet_check_impl(skb, type, key, inum, ifindex, expect_id);
}

#define ID_MAP_DEFINITION(id_map)                                                                                                                                                                      \
    struct bpf_map_def SEC("maps") id_map = {                                                                                                                                                          \
	.type = BPF_MAP_TYPE_ARRAY,                                                                                                                                                                    \
	.key_size = sizeof(uint32_t),                                                                                                                                                                  \
	.value_size = sizeof(uint32_t),                                                                                                                                                                \
	.max_entries = 2,                                                                                                                                                                              \
    }

__attribute__((always_inline))
static inline uint32_t get_filter_id(struct bpf_map_def *id_map) {
    uint32_t id_index = 0;
    uint32_t id = -1;
    uint32_t *pid = bpf_map_lookup_elem(id_map, &id_index);
	if (pid) {
	    id = *pid;
    }
    return id;
}

__attribute__((always_inline))
static inline void set_map_full_flag(struct bpf_map_def *id_map) {
    uint32_t flag_index = 1;
    uint32_t value = 1;
    bpf_map_update_elem(id_map, &flag_index, &value, 0);
}

__attribute__((always_inline))
static inline int tag_timestamp_softirq_compat(struct bpf_map_def *id_map, struct bpf_map_def *map, struct sk_buff *skb, u32 function_id, u8 type, u64 softirq_ts) {
    struct pingtrace_map_key key = {};
    struct pingtrace_map_value *ptmv;
    u32 inum = 0, ifindex = 0;
    u8 icmp_type = 0;
    u32 id = 0;
    int ret = 0;

    id = get_filter_id(id_map);
    if (!pt_packet_check_with_id(skb, &icmp_type, &key, &inum, &ifindex, id))
	    return -1;
    if (icmp_type != type)
	    return -1;
    ptmv = bpf_map_lookup_elem(map, &key);
    if (!ptmv)
	    ret = update_map_with_new_entry(map, &key, function_id, inum, ifindex, softirq_ts);
    else
	    update_map_with_exist_entry(ptmv, function_id, inum, ifindex, softirq_ts);
    if (ret == -E2BIG)
	    set_map_full_flag(id_map);
    return 0;
}

__attribute__((always_inline))
static inline int tag_timestamp_compat(struct bpf_map_def *id_map, struct bpf_map_def *map, struct sk_buff *skb, u32 function_id, u8 type) {
    return tag_timestamp_softirq_compat(id_map, map, skb, function_id, type, -1);
}