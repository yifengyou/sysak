/*
 * Copyright (C) 2018 Alibaba Group
 * All rights reserved.
 * Written by Wetp Zhang <wetp.zy@linux.alibaba.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/spinlock.h>

#define BBOX_MEM_MAX (100 << 20) /* 100M */

#define BBOX_SIZE PAGE_SIZE
#define BBOX_NAME_LEN 16

struct record_info {
	void *start;
	unsigned int size;
	unsigned int type;
	struct timespec64 mtime;
	char tsk_comm[TASK_COMM_LEN];
	char desc[BBOX_RECORD_DESC_LEN];
	int cpu;
	int pid;
	int state;
};

/* bbox_info is stored at the head of a bbox */
struct bbox_info {
	u64 magic;
	char name[BBOX_NAME_LEN];
	spinlock_t lock;
	int flags;
	void *data_base;
	void *data_end;
	union {
		struct bbox_ring {
			void *write_ptr;
			void *read_ptr;
		} ringbuf;
		struct bbox_record {
			unsigned int cnt;
			struct record_info arr[0];
		} records;
	};
};
