#ifndef __CGTRACE_H
#define __CGTRACE_H

#define TASK_COMM_LEN 16

struct memcg_usage {
	char comm[TASK_COMM_LEN];
	unsigned int pgsize;
	int knid;
	unsigned long ptid;
};

struct task_info {
	unsigned int pid;
	unsigned int tid;
	char comm[TASK_COMM_LEN];
	unsigned int pgsize;
	struct task_info *next;
};

struct memcg_mess {
	int knid;
	struct task_info *info;
	unsigned int task_num;
	struct memcg_mess *next;
};

#endif
