#define BPF_ANY	0
#define MAX_MONI_NR	1024

/* latency thresh:10ms*/
#define LAT_THRESH_NS	(10*1000*1000)
#define TASK_COMM_LEN	16
#define PERF_MAX_STACK_DEPTH	32
#define TASK_COMM_LEN	16
#define PERF_MAX_STACK_DEPTH	32

#ifdef __x86_64__
#define	TIF_NEED_RESCHED	3
#elif defined (__aarch64__)
#define TIF_NEED_RESCHED	1
#endif

#define CPU_ARRY_LEN	4

struct args {
	int flag;
	__u64 thresh;
};

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

struct event {
	__u32 ret, pid, cpu;
	__u64 delay, stamp;
	char comm[TASK_COMM_LEN];
};

struct max_sum {
	__u64 value;
	__u64 stamp;
	int cpu, pid;
	char comm[TASK_COMM_LEN];
};

struct summary {
	unsigned long num;
	__u64	total;
	struct max_sum max;
	int cpus[CPU_ARRY_LEN];
};

