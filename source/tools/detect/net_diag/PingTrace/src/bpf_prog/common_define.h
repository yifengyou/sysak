#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "map_define.h"

typedef u32 uint32_t;
typedef u64 uint64_t;
typedef u16 uint16_t;
typedef u8 uint8_t;

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

struct bpf_pingtrace_hdr
{
        uint8_t version;
        uint8_t num;
        uint16_t flags;
        uint16_t magic;
        uint16_t reserve;
        uint32_t id;
        uint32_t seq;
};

struct bpf_icmp_header
{
        uint8_t type;
        uint8_t code;
        uint16_t checksum;
        uint16_t id;
        uint16_t seq;
        struct bpf_pingtrace_hdr hdr;
};

#define E2BIG 7

#define ntohs(x) (__u16)__builtin_bswap16((__u16)(x))
#define ntohl(x) (__u32)__builtin_bswap32((__u32)(x))

#define BPF_ANY            0
#define NULL               ((void*)0)

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_ECHO		8	/* Echo Request			*/

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})