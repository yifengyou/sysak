/*
 * Author: Chen Tao
 * Create: Mon Jan 17 14:12:20 2022
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
//#include <linux/bpf.h>
#include "bpf_common.h"

/*
 * recv probe func: net_receive_skb、ip_rcv、tcp_v4_rcv
 * send probe func: tcp_transmit_skb、ip_finish_output、dev_queue_xmit
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} perf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10000);
	__type(key, struct tcptrace_map_key);
	__type(value, struct tcptrace_map_value);
} pt_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct tuple_info);
} tuple_map SEC(".maps");

/*
struct {
	__uint(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} perf_map SEC(".maps");
*/

SEC("kprobe/raw_sendmsg")
int __ip_queue_xmit_hook(struct pt_regs *ctx)
{
	struct tuple_info *tuple = NULL;
	struct sockaddr_in *usin = NULL;

	tuple = get_tuple_info(&tuple_map, PORT_VARS);
	if (!tuple) {
		return 0;
	}

	struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
	tag_raw_timestamp(&pt_map, msg, PT_KERN_RAW_SENDMSG, TCPTRACE_DIRECTION_OUT, tuple,
			false, ctx, &perf_map);
	return 0;
}
/*
SEC("kprobe/ip_finish_output2")
int ip_finish_output_hook(struct pt_regs *ctx)
{
	struct tuple_info *tuple;

	tuple = get_tuple_info(&tuple_map, PORT_VARS);
	if (!tuple) {
		return 0;
	}
	//struct sk_buff *skb = (void *)PT_REGS_PARM2(ctx);
	struct sock *sk = (void *)PT_REGS_PARM2(ctx);
	//tag_sock_timestamp(&pt_map, sk, PT_KERN_IP_FIN_OUTPUT, TCPTRACE_DIRECTION_OUT, tuple,
	//			false, ctx, &perf_map);

	return 0;
}
*/

SEC("kprobe/__dev_queue_xmit")
int dev_queue_xmit_hook(struct pt_regs *ctx)
{
	struct tuple_info *tuple = NULL;

	tuple = get_tuple_info(&tuple_map, PORT_VARS);
	if (!tuple) {
		return 0;
	}
	struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
	tag_timestamp(&pt_map, skb, PT_KERN_DEV_QUE_XMIT, TCPTRACE_DIRECTION_OUT, tuple,
			true, ctx, &perf_map);

	return 0;
}

SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv_hook(struct pt_regs *ctx)
{
	struct tuple_info *tuple;

	tuple = get_tuple_info(&tuple_map, PORT_VARS);
	if (!tuple) {
		return 0;
	} 

	struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
	tag_timestamp(&pt_map, skb, PT_KERN_TCP_V4_RCV, TCPTRACE_DIRECTION_IN, tuple,
				true, ctx, &perf_map);
	return 0;
}

SEC("kprobe/ip_rcv")
int ip_rcv_hook(struct pt_regs *ctx)
{
	struct tuple_info *tuple;

	tuple = get_tuple_info(&tuple_map, PORT_VARS);
	if (!tuple) {
		return 0;
	}

	struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
	tag_timestamp(&pt_map, skb, PT_KERN_IP_RCV, TCPTRACE_DIRECTION_IN, tuple,
				false, ctx, &perf_map);
	
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
	struct tuple_info *tuple;

	tuple = get_tuple_info(&tuple_map, PORT_VARS);
	if (!tuple) {
		return 0;
	}

	tag_timestamp(&pt_map, args->skb, PT_KERN_NET_RECV_SKB, TCPTRACE_DIRECTION_IN, tuple,
			false, args, &perf_map);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
