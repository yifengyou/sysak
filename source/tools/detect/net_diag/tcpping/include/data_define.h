/*
 * Author: Chen Tao
 * Create: Mon Jan 17 14:12:20 2022
 */

#ifndef TCPTRACE_DATA_DEFINE_H
#define TCPTRACE_DATA_DEFINE_H

#define TCPTRACE_MAP_ENTRY_NUM 8
#define TCPTRACE_MAX_RTT_NS 10000000000UL

enum TCPTRACE_VARS {
	PORT_VARS=0,
};

enum TCPTRACE_DIRCTION {
	TCPTRACE_DIRECTION_OUT = 0,
	TCPTRACE_DIRECTION_IN,
};

struct tuple_info {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t protol;
};
/*
 * function_id in tcptrace_map_entry
 */
enum tcptrace_function {
	/* send */
	PT_USER, 
	PT_KERN_RAW_SENDMSG,
	//PT_KERN_IP_FIN_OUTPUT, /* not trace now */
	PT_KERN_DEV_QUE_XMIT,
	/* recv */
	PT_KERN_NET_RECV_SKB,
	PT_KERN_IP_RCV,
	PT_KERN_TCP_V4_RCV,
	PT_MAX,
};

struct tcptrace_map_entry {
	uint32_t function_id;
	uint32_t padding;
	uint64_t ns;
};

struct tcptrace_map_value {
	struct tcptrace_map_entry entries[TCPTRACE_MAP_ENTRY_NUM];
};

struct tcptrace_map_key {
	uint32_t seq;
};

#endif //TCPTRACE_DATA_DEFINE_H
