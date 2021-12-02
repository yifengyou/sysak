#include <linux/version.h>
#include "bpf_common.h"

struct bpf_map_def SEC("maps") pt_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct pingtrace_map_key),
	.value_size = sizeof(struct pingtrace_map_value),
	.max_entries = 100,
};

SEC("kprobe/icmp_rcv")
int icmp_rcv_probe(struct pt_regs *ctx)
{
        struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
        tag_timestamp(&pt_map, skb, P_R_RX_ICMPRCV, ICMP_ECHO);
        return 0;
}


struct net_dev_xmit_args
{
        uint32_t pad[2];
        struct sk_buff *skb;
};

SEC("tracepoint/net/net_dev_xmit")
int net_dev_start_xmit_hook(struct net_dev_xmit_args *args)
{
        int ret;
        struct sk_buff *skb = args->skb;
        ret = tag_timestamp(&pt_map, skb, P_R_TX_DEVOUT, ICMP_ECHOREPLY);
        return 0;
}

struct netif_receive_skb_args
{
        uint64_t pad;
        struct sk_buff *skb;
};

SEC("tracepoint/net/netif_receive_skb")
int netif_rx_hook(struct netif_receive_skb_args *args)
{
        struct sk_buff *skb = args->skb;

        tag_timestamp(&pt_map, skb, P_R_RX_IPRCV, ICMP_ECHO);
        return 0;
}

char _license[] SEC("license") = "GPL";