#include "bpf_common_compat.h"

struct bpf_map_def SEC("maps") sched_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = PT_SCHED_NUM,
};

struct sched_wakeup_args
{
        uint64_t padding[3];
        pid_t pid;
};

SEC("tracepoint/sched/sched_wakeup")
int sched_wakeup_trace(struct sched_wakeup_args *args)
{
        u64 *expect_pid, pid;
        uint32_t idx = PT_SCHED_PID;
        u64 ts;

        pid = args->pid;
        expect_pid = bpf_map_lookup_elem(&sched_map, &idx);
        if (!expect_pid || pid != *expect_pid)
                return 0;
        idx = PT_SCHED_TS;
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&sched_map, &idx, &ts, 0);
        return 0;
}

struct bpf_map_def SEC("maps") irq_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = PT_IRQ_MAP_ENTRY_NUM,
};

struct softirq_entry_args
{
        uint64_t padding;
        int vec;
};

SEC("tracepoint/irq/softirq_raise")
int softirq_hook(struct softirq_entry_args *args)
{
        u32 cpu;
        u64 ts;
        u64 *ptr;

        if (args->vec != NET_RX_SOFTIRQ)
                return 0;
        cpu = bpf_get_smp_processor_id();
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&irq_map, &cpu, &ts, 0);
        return 0;
}

struct bpf_map_def SEC("maps") tx_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct pingtrace_map_key),
	.value_size = sizeof(struct pingtrace_map_value),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") rx_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct pingtrace_map_key),
	.value_size = sizeof(struct pingtrace_map_value),
	.max_entries = 100,
};

ID_MAP_DEFINITION(id_map);

SEC("kprobe/raw_local_deliver")
int raw_local_deliver_probe(struct pt_regs *ctx)
{
        struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
        tag_timestamp_compat(&id_map, &rx_map, skb, P_L_RX_SKDATAREADY, ICMP_ECHOREPLY);
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
        u32 cpu;
        u64 softirq_ts = -1;
        u64 *ts_ptr;
        
        cpu = bpf_get_smp_processor_id();
        ts_ptr = bpf_map_lookup_elem(&irq_map, &cpu);
        if (ts_ptr)
                softirq_ts = *ts_ptr;
        tag_timestamp_softirq_compat(&id_map, &rx_map, skb, P_L_RX_IPRCV, ICMP_ECHOREPLY, softirq_ts);
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
        struct sk_buff *skb = args->skb;
        tag_timestamp_compat(&id_map, &tx_map, skb, P_L_TX_DEVOUT, ICMP_ECHO);
        return 0;
}

struct net_dev_queue_args
{
        uint32_t pad[2];
        struct sk_buff *skb;
};

SEC("tracepoint/net/net_dev_queue")
int net_dev_queue_hook(struct net_dev_queue_args *args)
{
        struct sk_buff *skb = args->skb;
        tag_timestamp_compat(&id_map, &tx_map, skb, P_L_TX_DEVQUEUE, ICMP_ECHO);
        return 0;
}

char _license[] SEC("license") = "GPL";