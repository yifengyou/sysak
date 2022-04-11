/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQSLOWER_H
#define __RUNQSLOWER_H
#define TASK_COMM_LEN 16
#ifdef __x86_64__
#define	TIF_NEED_RESCHED	3
#elif defined (__aarch64__)
#define TIF_NEED_RESCHED	1
#endif

struct comm_item {
	char comm[TASK_COMM_LEN];
	unsigned long size;
};

struct args {
	__u64 min_us;
	pid_t targ_pid;
	pid_t targ_tgid;
	struct comm_item comm_i;
	int flag;
};

struct tharg {
	int fd;
	int ext_fd;
};

struct enq_info {
	union {
		unsigned int rqlen;
		__u64 pad;
	};
	__u64 ts;
};

struct env {
	pid_t pid;
	pid_t tid;
	unsigned long span;
	__u64 min_us;
	bool previous;
	bool verbose;
	void *fp;
	struct comm_item comm;
};

struct event {
	unsigned int rqlen;
	char task[TASK_COMM_LEN];
	char prev_task[TASK_COMM_LEN];
	
	__u64 delta_us;
	pid_t pid;
	pid_t prev_pid;
	int cpuid;
};

#endif /* __RUNQSLOWER_H */
