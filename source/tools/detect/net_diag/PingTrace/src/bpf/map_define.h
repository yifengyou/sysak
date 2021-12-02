#ifndef PINGTRACE_BPF_H
#define PINGTRACE_BPF_H

#define PINGTRACE_CODE_MAGIC 1
#define PINGTRACE_HDR_MAGIC 0x7ace
#define PINGTRACE_MAP_ENTRY_NUM 8
#define PINGTRACE_MAX_RTT_NS 10000000000UL

#define PINGTRACE_F_DONTADD 1

struct pingtrace_map_entry {
	uint16_t function_id;
	uint64_t ns;
	uint32_t net_inum;
	uint32_t ifindex;
} __attribute__((packed));

struct pingtrace_map_value {
	uint64_t softirq_ts;
	struct pingtrace_map_entry entries[PINGTRACE_MAP_ENTRY_NUM];
};

struct pingtrace_map_key {
	uint32_t id;
	uint32_t seq;
};

enum pingtrace_sched_map_index { PT_SCHED_PID = 0, PT_SCHED_TS, PT_SCHED_NUM };

#define PT_IRQ_MAP_ENTRY_NUM 4096

#endif