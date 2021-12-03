#ifndef PINGTRACE_COMMON_H
#define PINGTRACE_COMMON_H

#include "config.h"
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <unistd.h>

namespace pingtrace
{

enum output_type {
	OUTPUT_FILE,
	OUTPUT_CONSOLE,
};

enum display_type {
	DIS_IMAGE = 1,
	DIS_JSON = 2,
	DIS_JSON_FILE = 3,
	DIS_IMAGE_LOG = 4,
};

enum run_mode {
	MODE_AUTO,
	MODE_PINGPONG,
	MODE_COMPACT,
	MODE_UNDEFINED,
};

struct ping_exception {
	const char *str;
	int code;
	ping_exception(const char *str, int code) : str(str), code(code) {}
};

#define P_L_TX_USER 0
#define P_L_TX_DEVQUEUE 1
#define P_L_TX_DEVOUT 2
#define P_R_RX_ICMPRCV 3
#define P_R_TX_DEVOUT 4
#define P_L_RX_IPRCV 5
#define P_L_RX_SKDATAREADY 6
#define P_L_RX_WAKEUP 7
#define P_L_RX_USER 8
#define P_R_RX_IPRCV 9
#define P_L_RX_SOFTIRQ 10
#define P_HOST_POINT_NUM 11

#define P_L_ECS_POINT_NUM 11

#define P_M_TX_DEVECHO 11
#define P_M_RX_DEVECHO 12
#define P_M_TX_DEVREPLY 13
#define P_M_RX_DEVREPLY 14
#define PP_NUM P_M_RX_DEVREPLY

#define PINGTRACE_F_DONTADD 1

struct pingtrace_hdr {
	uint8_t version;
	uint8_t num;
	uint16_t flags;
	uint16_t magic;
	uint16_t reserve;
	uint32_t id;
	uint32_t seq;
};

struct pingtrace_timestamp {
	union {
		struct {
			uint32_t ns_id;
			uint32_t ifindex;
		};
		uint64_t machine_id;
	};
	uint16_t user_id;
	uint16_t function_id;
	uint32_t ts;
};

struct ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t hlen : 4;
	uint8_t version : 4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version : 4;
	uint8_t hlen : 4;
#endif
	uint8_t tos;	  // 服务类型
	uint16_t len;	 // 总长度
	uint16_t id;	  // 标识符
	uint16_t offset;      // 标志和片偏移
	uint8_t ttl;	  // 生存时间
	uint8_t protocol;     // 协议
	uint16_t checksum;    // 校验和
	struct in_addr ipsrc; // 32位源ip地址
	struct in_addr ipdst; // 32位目的ip地址
};

struct icmp {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
};

struct pingtrace_pkt {
	struct ip ip;
	struct icmp icmp;
	struct pingtrace_hdr hdr;
	struct pingtrace_timestamp entries[];

	static int min_packet_size() { return sizeof(pingtrace_hdr) + sizeof(pingtrace_timestamp) * config::packet_reserve_entry_num; }
	static int packet_size_to_entry_num(int size) { return (size - sizeof(pingtrace_hdr)) / sizeof(pingtrace_timestamp); }
} __attribute__((packed));

} // namespace pingtrace

#endif