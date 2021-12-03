#include <linux/version.h>
#include "bpf_common.h"

struct bpf_map_def SEC("maps") tx_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct pingtrace_map_key),
	.value_size = sizeof(struct pingtrace_map_value),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") rx_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct pingtrace_map_key),
	.value_size = sizeof(struct pingtrace_map_value),
	.max_entries = 100,
};

SEC("kprobe/dev_hard_start_xmit")
int net_dev_start_xmit_hook(struct pt_regs *ctx)
{
        int ret;
        struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
        ret = tag_timestamp_bidirect(skb, ICMP_ECHO, P_M_TX_DEVECHO, &rx_map, ICMP_ECHOREPLY, P_M_TX_DEVREPLY, &tx_map);
        return 0;
}

struct netif_rx_args
{
        uint64_t pad;
        struct sk_buff *skb;
};

SEC("tracepoint/net/netif_receive_skb")
int netif_rx_hook(struct netif_rx_args *args)
{
        int ret;
        ret = tag_timestamp_bidirect(args->skb, ICMP_ECHO, P_M_RX_DEVECHO, &rx_map, ICMP_ECHOREPLY, P_M_RX_DEVREPLY, &tx_map);
        return 0; 
}

char _license[] SEC("license") = "GPL";