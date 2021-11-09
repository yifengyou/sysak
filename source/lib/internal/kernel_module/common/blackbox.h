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

#ifndef BLACKBOX_H
#define BLACKBOX_H

#include <linux/fs.h>
#include <linux/time.h>

#define BBOX_FLAG_MASK	0xffff0000
#define BBOX_FLAG_SHIFT	16


#define BBOX_TYPE_MASK	0x0000ffff
#define BBOX_TYPE_SHIFT	0

#define BBOX_TYPE_RING	(0 << BBOX_TYPE_SHIFT)
#define BBOX_TYPE_RECORD	(1 << BBOX_TYPE_SHIFT)


#define BBOX_DATA_TYPE_STRING	0x1
#define BBOX_DATA_TYPE_TRACE	0x2
#define BBOX_DATA_TYPE_DATA	0x3

#define BBOX_RECORD_DESC_LEN 16

#define BBOX_BUFF_MAGIC 0xe0e1e2e3e4e5e6e7ul

struct bbox_data_info {
	void *data;
	unsigned int size;
	unsigned int slot;
	struct timespec64 mtime;
	struct task_struct *task;
};

extern ssize_t bbox_write(unsigned int bbox_id,
			struct bbox_data_info *data_info);
extern ssize_t bbox_read(unsigned int bbox_id,
			struct bbox_data_info *data_info);
extern int bbox_alloc_record_slot(unsigned int bbox_id, unsigned int size,
			unsigned int type);
extern void bbox_record_clear(unsigned int bbox_id, int slot_id);
extern int bbox_alloc(const char *name, int flags);
extern void bbox_free(unsigned int bbox_id);
extern int bbox_alloc_dynamic(const char *name, int flags,
		unsigned int pages);
extern int bbox_ring_show(struct seq_file *seq, unsigned int bbox_id);
extern int bbox_record_show(struct seq_file *seq,
		unsigned int bbox_id, int slot_id);
extern void bbox_set_record_desc(unsigned int bbox_id,
		unsigned int slot, const char *desc);
extern void bbox_update_name(unsigned int bbox_id, const char *name);
#endif
