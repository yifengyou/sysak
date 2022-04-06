/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __IRQOFF_H
#define __IRQOFF_H

#define TASK_COMM_LEN	16

struct info {
	__u64 prev_counter;
};

struct args {
	__u64 threshold;
	__u64 period;
};

struct event {
	__u32 pid, cpu;
	__u64 delay;
	char comm[TASK_COMM_LEN];
};

#endif /* __LLCSTAT_H */
