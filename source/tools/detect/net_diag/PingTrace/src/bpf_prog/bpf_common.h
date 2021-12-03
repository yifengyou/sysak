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

// for centos 3.10 kernel
struct net___310{
	unsigned int proc_inum;
};

struct net_device___310{
        struct net___310 *nd_net;
        int ifindex;
};

static inline int read_ns_inum(struct sk_buff *skb, u32 *inum, u32 *ifindex)
{
        struct net *net;
        if(bpf_core_field_exists(net->ns.inum))
        {
                struct net_device *dev;
                
                if (bpf_core_read(&dev, sizeof(dev), &skb->dev))
                        return 0;
                if (bpf_core_read(&net, sizeof(net), &dev->nd_net.net))
                        return 0;
                if (bpf_core_read(inum, sizeof(*inum), &net->ns.inum))
                        return 0;
                if (bpf_core_read(ifindex, sizeof(*ifindex), &dev->ifindex))
                        return 0;
        }
        else
        {
                struct net___310 *net310;
                struct net_device___310 *dev310;
                if (bpf_core_read(&dev310, sizeof(dev310), &skb->dev))
                        return 0;
                if (bpf_core_read(&net310, sizeof(net310), &dev310->nd_net))
                        return 0;
                if (bpf_core_read(inum, sizeof(*inum), &net310->proc_inum))
                        return 0;
                if (bpf_core_read(ifindex, sizeof(*ifindex), &dev310->ifindex))
                        return 0;
        }
        
        return 1;
}

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
        if (!read_ns_inum(skb, inum, ifindex))
                return 0;
        key->seq = ntohl(icmph.hdr.seq);
        key->id = ntohl(icmph.hdr.id);

        if (expect_id != (u32)(-1) && expect_id != key->id)
                return 0;

        *type = icmph.type;
        return 1;
}

static inline int
pt_packet_check(struct sk_buff *skb, u8 *type, struct pingtrace_map_key *key, u32 *inum, u32 *ifindex)
{
        return pt_packet_check_impl(skb, type, key, inum, ifindex, -1);
}

static inline int
pt_packet_check_with_id(struct sk_buff *skb, u8 *type, struct pingtrace_map_key *key, u32 *inum, u32 *ifindex, u32 expect_id)
{
        return pt_packet_check_impl(skb, type, key, inum, ifindex, expect_id);
}

static inline int
pt_packet_check_verbose(struct sk_buff *skb, u8 *type, struct pingtrace_map_key *key, u32 *inum, u32 *ifindex)
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

        if (bpf_probe_read(&iph, sizeof(iph), piph)) {
                bpf_printk("pingtrace: read iph failed\n");
                return 0;
        }
        if (iph.protocol != IPPROTO_ICMP)
                return 0;
        bpf_printk("pingtrace: catch a icmp packet\n");
        picmph = (struct bpf_icmp_header *)((void *)(piph) + iph.ihl*4);
        bpf_printk("pingtrace: read icmph\n");
        if (bpf_probe_read(&icmph, sizeof(icmph), picmph))
                return 0;
        bpf_printk("pingtrace: compare icmp type\n");
        if (icmph.type != ICMP_ECHO && icmph.type != ICMP_ECHOREPLY)
                return 0;
        bpf_printk("pingtrace: compare code magic\n");
        if (icmph.code != PINGTRACE_CODE_MAGIC)
                return 0;
        bpf_printk("pingtrace: compare hdr magic\n");
        if (ntohs(icmph.hdr.magic) != PINGTRACE_HDR_MAGIC)
                return 0;
        bpf_printk("pingtrace: compare flag\n");
        if (ntohs(icmph.hdr.flags) & PINGTRACE_F_DONTADD)
                return 0;
        bpf_printk("pingtrace: read ifindex\n");
        if (!read_ns_inum(skb, inum, ifindex))
                return 0;
        key->seq = ntohl(icmph.hdr.seq);
        key->id = ntohl(icmph.hdr.id);
        *type = icmph.type;
        return 1;
}

__attribute__((always_inline))
static inline int tag_timestamp_softirq(struct bpf_map_def *map, struct sk_buff *skb, u32 function_id, u8 type, u64 softirq_ts)
{
        struct pingtrace_map_key key = {};
        struct pingtrace_map_value *ptmv = NULL;
        u32 inum = 0, ifindex = 0;
        u8 icmp_type = 0;

        if (!pt_packet_check(skb, &icmp_type, &key, &inum, &ifindex))
                return -1;
        if (icmp_type != type)
                return -1;
        ptmv = bpf_map_lookup_elem(map, &key);
        if (!ptmv)
                update_map_with_new_entry(map, &key, function_id, inum, ifindex, softirq_ts);
        else
                update_map_with_exist_entry(ptmv, function_id, inum, ifindex, softirq_ts);
        return 0;
}

__attribute__((always_inline))
static inline int tag_timestamp(struct bpf_map_def *map, struct sk_buff *skb, u32 function_id, u8 type)
{
        return tag_timestamp_softirq(map, skb, function_id, type, -1);
}

__attribute__((always_inline))
static inline int tag_timestamp_verbose_softirq(struct bpf_map_def *map, struct sk_buff *skb, u32 function_id, u8 type, u64 softirq_ts)
{
        struct pingtrace_map_key key = {};
        struct pingtrace_map_value *ptmv = NULL;
        u32 inum = 0, ifindex = 0;
        u8 icmp_type = 0;

        if (!pt_packet_check_verbose(skb, &icmp_type, &key, &inum, &ifindex))
                return -1;
        if (icmp_type != type)
                return -1;
        ptmv = bpf_map_lookup_elem(map, &key);
        if (!ptmv)
                update_map_with_new_entry(map, &key, function_id, inum, ifindex, softirq_ts);
        else
                update_map_with_exist_entry(ptmv, function_id, inum, ifindex, softirq_ts);
        return 0;
}

__attribute__((always_inline))
static inline int tag_timestamp_verbose(struct bpf_map_def *map, struct sk_buff *skb, u32 function_id, u8 type)
{
        return tag_timestamp_verbose_softirq(map, skb, function_id, type, -1);
}

__attribute__((always_inline))
static inline int tag_timestamp_bidirect(struct sk_buff *skb, u8 type1, u32 function_id1, struct bpf_map_def *map1, u8 type2, u32 function_id2, struct bpf_map_def *map2)
{
        struct pingtrace_map_key key = {};
        struct pingtrace_map_value *ptmv;
        u32 inum = 0, ifindex = 0;
        u8 icmp_type;
        struct bpf_map_def * map;
        u32 function_id;

        if (!pt_packet_check(skb, &icmp_type, &key, &inum, &ifindex))
                return -1;
        if (icmp_type != type1 && icmp_type != type2)
                return -1;
        
        map = map1;
        function_id = function_id1;
        if (icmp_type == type2) {
                map = map2;
                function_id = function_id2;
        }
        ptmv = bpf_map_lookup_elem(map, &key);
        if (!ptmv)
                update_map_with_new_entry(map, &key, function_id, inum, ifindex, -1);
        else
                update_map_with_exist_entry(ptmv, function_id, inum, ifindex, -1);
        return 0;
}
