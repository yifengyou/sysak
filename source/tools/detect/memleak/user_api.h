#ifndef __USER_API__
#define __USER_API__

#define MONITOR_TIME (300)
#define MONITOR_RATE (20) /* 20% */

#include "common.h"

typedef enum _memleak_type {
    MEMLEAK_TYPE_SLAB = 1,
    MEMLEAK_TYPE_PAGE,
    MEMLEAK_TYPE_VMALLOC,
} memleak_type;

struct memleak_settings {
	memleak_type type;
	int monitor_time;/*default 300 seconds */
	int rate;
	char name[NAME_LEN];
	int ext;/*extension function */
};

struct max_object {
	char slabname[NAME_LEN];
	void *ptr;
	int object_size;
	unsigned long  object_num;
	unsigned long  similar_object;
};
struct user_result {
	int num;
	struct max_object *objects;
	struct user_alloc_desc *desc;
};

struct user_alloc_desc {
    int pid;
	int mark;
	int order;
    const void *ptr;
    char comm[TASK_COMM_LEN];
    char function[NAME_LEN];
	unsigned long long call_site;
    unsigned long long ts;
    unsigned long long  backtrace[];
};

struct user_call_site {
	unsigned long long call_site;
	int nr;
	int mark_nr;
	char function[NAME_LEN];
};

#endif
