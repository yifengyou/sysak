/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQSLOWER_H
#define __RUNQSLOWER_H
#define TASK_COMM_LEN 16
#ifdef __x86_64__
#define	TIF_NEED_RESCHED	3
#elif defined (__aarch64__)
#define TIF_NEED_RESCHED	1
#endif


struct args {
	__u64 min_us;
	pid_t targ_pid;
	pid_t targ_tgid;
	int flag;
};

struct tharg {
	int fd;
	int ext_fd;
};

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
	void *fp;
};

struct event {
	char task[TASK_COMM_LEN];
	char prev_task[TASK_COMM_LEN];
	
	__u64 delta_us;
	pid_t pid;
	pid_t prev_pid;
	int cpuid;
};

#endif /* __RUNQSLOWER_H */
