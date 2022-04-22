/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __IRQOFF_H
#define __IRQOFF_H

#define TASK_COMM_LEN	16

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
	__u64 delay;
	char comm[TASK_COMM_LEN];
};

struct ksym {
	long addr;
	char *name;
};

#endif /* __LLCSTAT_H */
