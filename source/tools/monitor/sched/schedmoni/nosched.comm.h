#define BPF_ANY	0
#define MAX_MONI_NR	1024

/* latency thresh:10ms*/
#define LAT_THRESH_NS	(10*1000*1000)
#define TASK_COMM_LEN	16
#define PERF_MAX_STACK_DEPTH	32
#define TASK_COMM_LEN	16
#define PERF_MAX_STACK_DEPTH	32

struct ksym {
	long addr;
	char *name;
};

struct key_t {
	__u32 ret;
};

struct latinfo {
	__u64 last_seen_need_resched_ns;
	int ticks_without_resched;
};
