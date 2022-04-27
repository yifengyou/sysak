/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __IRQOFF_H
#define __IRQOFF_H

#define TASK_COMM_LEN	16
#define CPU_ARRY_LEN	4

struct info {
	__u64 prev_counter;
};

struct tm_info {
	__u64 last_stamp;
};

struct arg_info {
	__u64 thresh;
};

struct event {
	__u32 ret, pid, cpu;
	__u64 delay, stamp;
	char comm[TASK_COMM_LEN];
};

struct ksym {
	long addr;
	char *name;
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
#endif /* __LLCSTAT_H */

