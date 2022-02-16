#ifndef _RTRACE_COMMON_BPF_H_
#define _RTRACE_COMMON_BPF_H_

#define TASK_COMM_LEN 16
#define FUNCNAME_MAX_LEN 32
#define MAC_HEADER_SIZE 14
#define FILTER_RULES_MAX_NUM 10

#define TO_STR(a) #a
#define TO_STRING(a) TO_STR(a)

#define FILTER_MAP_DEFAULT_KEY 0
#define FLOW_MAP_DEFAULT_VAL ((__u64)(0x0123456776543210))
typedef uint64_t rtrace_mask_t;
#define MAX_NUM_BYTES (0xff + 1)
#define MAX_STACK 5
#define MAX_ENTRIES 10240
#define RTRACE_LSHIFT(nbits) ((rtrace_mask_t)1 << (nbits))
#define RTRACE_MASK(nbits) (RTRACE_LSHIFT(nbits) - 1)
#define RTRACE_ALIGN(n) n
#define TEST_NBITS_SET(num, nbits) ((num)&RTRACE_LSHIFT(nbits))
// #define ADDREF(a) &##a ERROR
#define ADDREF(a) &a
#define ENUM_TO_MAP_NAME(enum_type) enum_type##_map
#define ENUM_TO_REF_MAP(enum_type) ADDREF(ENUM_TO_MAP_NAME(enum_type))
#define ENUM_TO_STRUCT(enum_type) \
    struct enum_type##_struct

#define ENUM_TO_FUNC_NAME(prefix, enum_type) prefix_##enum_type

#define TYPE_TO_ENUM(type) (((type) << 16) >> 16)
#define TYPE_TO_CPU(type) ((type) >> 16)

#define TYPE_SET_CPU(type, cpu) ((type) + ((cpu) << 16))

#define IPHDR_VALID(iphdr) ((iphdr)->saddr != 0)
#define TCPHDR_VALID(cd) ((cd)->transport_header != (u16)~0)

// 0 - 6 bit 6 - 12 bit 31 - 32 bit
#define SET_MAJOR_TYPE(num, val) (((num) & (~(0x3f))) | ((val) & (0x3f)))
#define SET_MINOR_TYPE(num, val) (((num) & (~(0x3f << 6))) | (((val) & (0x3f)) << 6))
#define SET_SEND_RECV(num, val) ((num) & (~(1u << 31)) | (((val)&0x1)) << 31)
#define GET_MAJOR_TYPE(num) ((num) & (0x3f))
#define GET_MINOR_TYPE(num) (((num) >> 6) & (0x3f))
#define GET_SEND_RECV(num) (((num) >> 31) & 0x1)

#ifndef __CONCAT //for bpf program.
#define __CONCAT(a, b) a##b
#endif
#define CONCATENATE(a, b) __CONCAT(a, b)

#define PLACEHOLDER_NUM1 0x888
#define PLACEHOLDER_NUM(no) CONCATENATE(PLACEHOLDER_NUM, no)
#define INSTERT_PLACEHOLDER(type, no)     \
    type placeholder_##no;                \
    asm volatile("%0 = %1"                \
                 : "=r"(placeholder_##no) \
                 : "i"(PLACEHOLDER_NUM(no)));

#define LOOKUP_PLACEHOLDER(no) placeholder_##no
#define CONTAINER_ID_LEN 128

#define KPROBE_NAME(func) kprobe__##func
#define ZERO_OR_EQUAL(a, b) ((a) == 0 || (a) == (b))

enum
{
    BASIC_INFO = 0,
    CGROUP,
    STACK,
    KRETPROBE, // Get the return parameter of the function
    LINEPROBE,
    ENUM_END,
};

#define MAX_BUFFER_SIZE 512
#define BUFFER_START_OFFSET 8
struct buffer
{
    uint64_t offset;
    uint8_t buffer[MAX_BUFFER_SIZE];
};

struct cache_data
{
    void *ctx;
    struct sock *sk;
    struct sk_buff *skb;
    struct buffer *buffer;
    char *head;
    // char *data;
#if defined(__VMLINUX_H__)
    struct iphdr ih;
    struct tcphdr th;
    struct tcp_skb_cb tsc;
#else
    int ih[5];
    int th[5];
    int tsc[12];
#endif
    uint16_t transport_header;
    uint16_t network_header;
    uint8_t send;
    uint32_t sk_protocol;
};

struct addr_pair
{
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
};

struct pid_info
{
    uint32_t pid;
    char comm[TASK_COMM_LEN];
};

// The addition of s is to avoid duplication with stack_info of vmlinux.h.
ENUM_TO_STRUCT(STACK)
{
    uint64_t kern_stack[MAX_STACK];
};

struct filter_meta {
    int pid;
    struct addr_pair ap;
};

struct filter_map_key
{
    struct filter_meta fm[FILTER_RULES_MAX_NUM];
    uint32_t protocol;
    int cnt;
};

struct tid_map_key
{
    uint32_t tid;
    uint32_t bp;
};

#define CONSTRUCT_BPF_PROGRAM_NAME(sk_pos, skb_pos) \
    kprobe_sk_##sk_pos##skb_##skb_pos

ENUM_TO_STRUCT(BASIC_INFO)
{
    uint64_t mask;
    uint64_t ip;
    uint64_t ts;
    uint32_t seq;
    uint32_t end_seq;
    uint32_t rseq;
    uint32_t rend_seq;
    struct addr_pair ap;
    struct pid_info pi;
    uint64_t ret;
};

ENUM_TO_STRUCT(CGROUP)
{
    uint32_t inum;
    uint64_t cgroupid;
};

#define DECLARE_AND_INIT_STRUCT(enum_type, name) \
    ENUM_TO_STRUCT(enum_type)                    \
    name = {0}

#define DECLARE_STRUCT_PTR(enum_type, name) \
    ENUM_TO_STRUCT(enum_type) * name

#define DECLARE_STRUCT(enum_type, name) \
    ENUM_TO_STRUCT(enum_type)           \
    name

#endif
