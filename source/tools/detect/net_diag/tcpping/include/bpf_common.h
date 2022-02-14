/*
 * Author: Chen Tao
 * Create: Mon Jan 17 14:12:20 2022
 */
#ifndef TCPTRACE_COMMON_H
#define TCPTRACE_COMMON_H
//#include "../vmlinux/vmlinux.h"
#include <vmlinux.h>
#include "data_define.h"
#include <bpf/bpf_core_read.h>


#define ntohs(x) (u16)__builtin_bswap16((u16)(x))
#define ntohl(x) (u32)__builtin_bswap32((u32)(x))

#define tcp_bpf_printk(fmt, ...) 			\
({ 							\
	char ____fmt[] = fmt; 				\
	bpf_trace_printk(____fmt, sizeof(____fmt), 	\
			##__VA_ARGS__); 		\
}) 							\

#define BPF_ANY            0
#ifndef NULL
#define NULL               ((void*)0)
#endif

#define OFFSET_OF(type, member) (unsigned long)(&(((type*)0)->member))
#define SKB_OFFSET_DATA OFFSET_OF(struct sk_buff, data)
#define SKB_OFFSET_HEAD OFFSET_OF(struct sk_buff, head)
#define SKB_OFFSET_TRANSPORT_HEADER OFFSET_OF(struct sk_buff, transport_header)
#define SKB_OFFSET_NETWORK_HEADER OFFSET_OF(struct sk_buff, network_header)

static inline void tcptrace_map_value_clear(struct tcptrace_map_value *ptmv)
{
	int i;
#pragma unroll
	for(i = 0; i < TCPTRACE_MAP_ENTRY_NUM; ++i) {
		ptmv->entries[i].function_id = 0;
		ptmv->entries[i].ns = 0;
		ptmv->entries[i].padding = 0;
	}
}

static inline void tcptrace_map_value_fill(struct tcptrace_map_value *ptmv,
					   struct tcptrace_map_value *map)
{
	int i;
#pragma unroll
	for(i = 0; i < TCPTRACE_MAP_ENTRY_NUM; ++i) {
		map->entries[i].function_id = ptmv->entries[i].function_id;
		map->entries[i].ns = ptmv->entries[i].ns;
		map->entries[i].padding = ptmv->entries[i].padding;
#ifdef DEBUG
		tcp_bpf_printk("func id:%d, ns:%llu\n", ptmv->entries[i].function_id,
				ptmv->entries[i].ns);
#endif
	}
}

static inline void update_map_with_new_entry(void *map, struct tcptrace_map_key *key,
					     int direction, u32 function_id)
{
	struct tcptrace_map_value ptmv;

	tcptrace_map_value_clear(&ptmv);
	ptmv.entries[function_id].function_id = function_id;
	ptmv.entries[function_id].ns = bpf_ktime_get_ns();
	ptmv.entries[function_id].padding = direction;
	bpf_map_update_elem(map, key, &ptmv, BPF_ANY);
}

static inline void
update_map_with_exist_entry(struct tcptrace_map_value *ptmv, u32 function_id,
			    int direction)
{
	int idx = 0;
	u64 ns;

	ns = bpf_ktime_get_ns();
	if (ptmv->entries[function_id].function_id &&
			(ptmv->entries[0].ns + TCPTRACE_MAX_RTT_NS) <= ns) {
		tcptrace_map_value_clear(ptmv);
		idx = 0;
		goto ok;
	}

ok:
	ptmv->entries[function_id].function_id = function_id;
	ptmv->entries[function_id].ns = ns;
	ptmv->entries[function_id].padding = direction;
}

static inline int tcptrace_packet_raw_check(struct msghdr *msg,
		struct tuple_info *tuple,
		u32 function_id,
		int direction,
		struct tcptrace_map_key *key)
{
	u32 dst_ip;
	char *ptr = NULL;
	struct sockaddr_in *usin = NULL;

	BPF_CORE_READ_INTO(&usin, msg, msg_name);
	BPF_CORE_READ_INTO(&dst_ip, usin, sin_addr);

	if (dst_ip != tuple->dst_ip)
		return 0;

	return 1;
}

static inline int tcptrace_packet_sock_check(struct sock *sk,
		struct tuple_info *tuple,
		u32 function_id,
		int direction,
		struct tcptrace_map_key *key)
{
	u16 src_port = 0, dst_port;
	u32 src_ip, dst_ip;
	//u8 protocol;
	char *ptr = NULL;

	BPF_CORE_READ_INTO(&src_ip, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&dst_ip, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);

	if (direction == TCPTRACE_DIRECTION_OUT) {
		if ((dst_ip != tuple->dst_ip) || (src_ip != tuple->src_ip) ||
				(dst_port != tuple->dst_port) ||
				(src_port != tuple->src_port))
			return 0;
	} else if (direction == TCPTRACE_DIRECTION_IN) {
		if ((src_ip != tuple->dst_ip) || (dst_ip != tuple->src_ip) ||
				(src_port != tuple->dst_port) ||
				(dst_port != tuple->src_port))
			return 0;
	} else {
		return 0;
	}

	return 1;
}

static inline int tcptrace_packet_check(struct sk_buff *skb,
		struct tuple_info *tuple,
		u32 function_id,
		int direction,
		struct tcptrace_map_key *key)
{
	struct iphdr *piph;
	struct iphdr iph;

	struct tcphdr *ptcph;
	struct tcphdr tcph;
	u16 network_header;
	void *head = NULL;
	u16 src_port, dst_port;
	u32 src_ip, dst_ip;
	char *ptr = NULL;

	if (bpf_probe_read(&network_header, sizeof(network_header),
				(void *)(skb)+SKB_OFFSET_NETWORK_HEADER)) {
		tcp_bpf_printk("read network_header failed, func id:%u\n, network_header:%u", function_id, network_header);
		return 0;
	}
	if (bpf_probe_read(&head, sizeof(head), (void *)(skb)+SKB_OFFSET_HEAD)) {
		tcp_bpf_printk("read head failed, func id:%u\n, head:%p", function_id, head);
		return 0;
	}
	/* 发包流程中2、3层获取不到头部信息 */
	piph = (struct iphdr*)(head+network_header);
	if (bpf_probe_read(&iph, sizeof(iph), piph)) {
		tcp_bpf_printk("read ipheader failed, func id:%u, piph:%p\n", function_id, piph);
		tcp_bpf_printk("read ipheader failed, head:%p, neteork_header:%u\n", head, network_header);
		return 0;
	}
	src_ip = iph.saddr;
	dst_ip = iph.daddr;

	if (iph.protocol != IPPROTO_TCP)
		return 0;

	ptcph = (struct tcphdr *)((void *)(piph) + iph.ihl * 4);
	if (bpf_probe_read(&tcph, sizeof(tcph), ptcph)) {
		tcp_bpf_printk("read tcp header failed, func id:%u\n", function_id);
		return 0;
	}
	dst_port = ntohs(tcph.dest);
	src_port = ntohs(tcph.source);
#ifdef DEBUG
	tcp_bpf_printk("1===src_port:%u: dst_port:%u, func id:%u\n", src_port, dst_port, function_id);
	tcp_bpf_printk("1===src_ip:%u, dst_ip:%u\n", src_ip, dst_ip);
	tcp_bpf_printk("2===tuple src_port%u, dst_port:%u\n", tuple->src_port, tuple->dst_port);
	tcp_bpf_printk("2===tuple src_ip:%u, dst_ip:%u\n", tuple->src_ip, tuple->dst_ip);
#endif

	if (direction == TCPTRACE_DIRECTION_OUT) {
		/* 根据四元组确定trace报文 */
		if ((dst_ip != tuple->dst_ip) || (src_ip != tuple->src_ip) ||
				(dst_port != tuple->dst_port) ||
				(src_port != tuple->src_port))
			return 0;
	} else if (direction == TCPTRACE_DIRECTION_IN) {
		if ((src_ip != tuple->dst_ip) || (dst_ip != tuple->src_ip) ||
				(src_port != tuple->dst_port) ||
				(dst_port != tuple->src_port))
			return 0;
	} else {
		return 0;
	}

	/* 发包流程中二层和三层没有seq有效信息，因此这里默认为0来识别 */
	if (function_id == PT_KERN_DEV_QUE_XMIT) {
		key->seq = 0;
	} else {
		key->seq = tcph.seq;
	}

	return 1;
}

__attribute__((always_inline)) static inline struct tuple_info* get_tuple_info(void *map, int key){
	struct tuple_info *ret = bpf_map_lookup_elem(map, &key);
	if (!ret) {
		return NULL;
	}
	return ret;
}

__attribute__((always_inline)) static inline void set_tuple_info(void *map, int key, int value){
	bpf_map_update_elem(map, &key, &value, BPF_ANY);
}

__attribute__((always_inline)) static inline int tag_raw_timestamp(void *map,
								struct msghdr *msg,
								u32 function_id,
								int direction,
								struct tuple_info *tuple,
								bool report,
								void *ctx,
								void *perf_map)
{
	struct tcptrace_map_key key = {0};
	struct tcptrace_map_value *ptmv = NULL;
	struct tcptrace_map_value value = {0};

	if (!tcptrace_packet_raw_check(msg, tuple, function_id, direction, &key))
		return -1;

	update_map_with_new_entry(map, &key, direction, function_id);

	return 0;
}

__attribute__((always_inline)) static inline int tag_sock_timestamp(void *map,
								struct sock *sk,
								u32 function_id,
								int direction,
								struct tuple_info *tuple,
								bool report,
								void *ctx,
								void *perf_map)
{
	struct tcptrace_map_key key = {0};
	struct tcptrace_map_value *ptmv = NULL;
	struct tcptrace_map_value value = {0};

	if (!tcptrace_packet_sock_check(sk, tuple, function_id, direction, &key))
		return -1;

	ptmv = bpf_map_lookup_elem(map, &key);
	if (!ptmv) {
		update_map_with_new_entry(map, &key, direction, function_id);
	} else {
		update_map_with_exist_entry(ptmv, function_id, direction);
		if (report) {
			bpf_perf_event_output(ctx, perf_map, BPF_F_CURRENT_CPU, ptmv,
					sizeof(struct tcptrace_map_value));
			bpf_map_delete_elem(map, &key);
		}

	}

	return 0;
}

__attribute__((always_inline)) static inline int tag_timestamp(void *map,
								struct sk_buff *skb,
								u32 function_id,
								int direction,
								struct tuple_info *tuple,
								bool report,
								void *ctx,
								void *perf_map)
{
	struct tcptrace_map_key key = {0};
	struct tcptrace_map_value *ptmv = NULL;
	struct tcptrace_map_value value = {0};

	if (!tcptrace_packet_check(skb, tuple, function_id, direction, &key))
		return -1;
#ifdef DEBUG
	tcp_bpf_printk("skb seq:%u, func id:%u\n", key.seq, function_id);
#endif
	ptmv = bpf_map_lookup_elem(map, &key);
	if (!ptmv) {
		update_map_with_new_entry(map, &key, direction, function_id);
	} else {
		update_map_with_exist_entry(ptmv, function_id, direction);
		if (report) {
			tcptrace_map_value_fill(ptmv, &value);
			bpf_perf_event_output(ctx, perf_map, BPF_F_CURRENT_CPU, ptmv,
					sizeof(struct tcptrace_map_value));
			bpf_map_delete_elem(map, &key);
		}

	}

	return 0;
}
#endif //TCPTRACE_COMMON_H
