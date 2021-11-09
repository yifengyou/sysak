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

#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/rtc.h>
#include <linux/mm.h>
#include <linux/radix-tree.h>

#include "proc.h"
#include "blackbox.h"
#include "internal.h"

#define DEFAULT_BBOX_SIZE 0x2000000
static unsigned int bbox_total_size = DEFAULT_BBOX_SIZE;
static DEFINE_SPINLOCK(bbox_alloc_lock);
static void *bbox_vmalloc_base;
static unsigned long *bbox_map;
static unsigned int bbox_max_id;
static unsigned int bbox_latest_id;

static unsigned long *bbox_dyn_map;
static unsigned int bbox_dynamic_max;
static unsigned long bbox_dynamic_start;
RADIX_TREE(bbox_dynamic_tree, GFP_NOWAIT);

static inline unsigned int bbox_id_to_dyn_idx(unsigned int bbox_id)
{
	return bbox_id - bbox_max_id - 1;
}

static inline unsigned int dyn_idx_to_bbox_id(unsigned int idx)
{
	return idx + bbox_max_id + 1;
}

static inline struct bbox_info *get_bbox(unsigned int bbox_id)
{
	unsigned idx = bbox_id;

	if (!bbox_vmalloc_base)
		return NULL;

	if (idx < bbox_max_id)
		return bbox_vmalloc_base + (idx * BBOX_SIZE);

	idx = bbox_id_to_dyn_idx(bbox_id);
	if (idx >= bbox_dynamic_max || !bbox_dyn_map)
		return NULL;

	return radix_tree_lookup(&bbox_dynamic_tree, idx);
}

static inline int bbox_type(struct bbox_info *bbox)
{
	return bbox->flags & BBOX_TYPE_MASK;
}

static inline void bbox_lock(struct bbox_info *bbox,
		unsigned long *flags)
{
	spin_lock_irqsave(&bbox->lock, *flags);
}

static inline void bbox_unlock(struct bbox_info *bbox,
		unsigned long flags)
{
	spin_unlock_irqrestore(&bbox->lock, flags);
}

static inline void *bbox_record_top(struct bbox_info *bbox)
{
	if (bbox->records.cnt)
		return bbox->records.arr[bbox->records.cnt - 1].start;
	else
		return bbox->data_end;
}

static inline int avail_size(struct bbox_info *bbox)
{
	if (bbox_type(bbox) == BBOX_TYPE_RING)
		return bbox->data_end - bbox->ringbuf.write_ptr;
	else
		return bbox_record_top(bbox) - bbox->data_base;
}

static ssize_t bbox_ring_write(struct bbox_info *bbox,
		struct bbox_data_info *data_info)
{
	int size = data_info->size;
	int tail_size = avail_size(bbox);
	int bbox_size = bbox->data_end - bbox->data_base;

	if (likely(size <= tail_size)) {
		memcpy(bbox->ringbuf.write_ptr, data_info->data, size);
		bbox->ringbuf.write_ptr += size;
	} else {
		if (size > bbox_size)
			size = bbox_size;

		if (tail_size > 0)
			memcpy(bbox->ringbuf.write_ptr,
					data_info->data, tail_size);
		memcpy(bbox->data_base,
				data_info->data + tail_size, size - tail_size);
		bbox->ringbuf.write_ptr = bbox->data_base + (size - tail_size);
	}

	return size;
}

static ssize_t bbox_record_write(struct bbox_info *bbox,
		struct bbox_data_info *data_info)
{
	struct record_info *r_info;
	unsigned int size = data_info->size;
	unsigned int slot = data_info->slot;

	if (slot >= bbox->records.cnt)
		return -EINVAL;

	r_info = &bbox->records.arr[slot];
	getnstimeofday64(&r_info->mtime);
	size = min(size, r_info->size);
	memcpy(r_info->start, data_info->data, size);
	if (virt_addr_valid(data_info->task)) {
		strncpy(r_info->tsk_comm, data_info->task->comm, TASK_COMM_LEN);
		r_info->cpu = task_cpu(data_info->task);
		r_info->pid = data_info->task->pid;
		r_info->state = data_info->task->state;
	}
	return size;
}

ssize_t bbox_write(unsigned int bbox_id, struct bbox_data_info *data_info)
{
	struct bbox_info *bbox;
	unsigned long flags;
	int ret = -EINVAL;

	if (!data_info || !data_info->data)
		return ret;

	bbox = get_bbox(bbox_id);
	if (!bbox)
		return ret;

	bbox_lock(bbox, &flags);

	if (bbox_type(bbox) == BBOX_TYPE_RING)
		ret = bbox_ring_write(bbox, data_info);
	else
		ret = bbox_record_write(bbox, data_info);

	bbox_unlock(bbox, flags);
	return ret;
}

static ssize_t bbox_ring_read(struct bbox_info *bbox,
		struct bbox_data_info *data_info)
{
	unsigned int count = 0, avl_sz, size = data_info->size;
	void *read_end = READ_ONCE(bbox->ringbuf.write_ptr);

	if (bbox->ringbuf.read_ptr > read_end) {
		avl_sz = bbox->data_end - bbox->ringbuf.read_ptr;
		count = min(size, avl_sz);
		memcpy(data_info->data, bbox->ringbuf.read_ptr, count);
		size -= count;
		bbox->ringbuf.read_ptr += count;
		if (bbox->ringbuf.read_ptr >= bbox->data_end)
			bbox->ringbuf.read_ptr = bbox->data_base;
	}

	if (!size)
		return count;

	avl_sz = read_end - bbox->ringbuf.read_ptr;
	size = min(avl_sz, size);
	if (size) {
		memcpy(data_info->data + count, bbox->ringbuf.read_ptr, size);
		bbox->ringbuf.read_ptr += size;
	}

	count += size;
	return count;
}

static ssize_t bbox_record_read(struct bbox_info *bbox,
		struct bbox_data_info *data_info)
{
	struct record_info *r_info;
	unsigned long flags;
	unsigned int slot = data_info->slot;
	unsigned int size = data_info->size;

	bbox_lock(bbox, &flags);

	if (slot >= bbox->records.cnt) {
		bbox_unlock(bbox, flags);
		return -EINVAL;
	}

	r_info = &bbox->records.arr[slot];
	size = min(size, r_info->size);
	memcpy(data_info->data, r_info->start, size);
	memcpy(&data_info->mtime, &r_info->mtime,
			sizeof(struct timespec64));
	bbox_unlock(bbox, flags);
	return size;
}

ssize_t bbox_read(unsigned int bbox_id, struct bbox_data_info *data_info)
{
	struct bbox_info *bbox;
	int ret = -EINVAL;

	if (!data_info || !data_info->data || data_info->size <= 0)
		return ret;

	bbox = get_bbox(bbox_id);
	if (!bbox)
		return ret;

	if (bbox_type(bbox) == BBOX_TYPE_RING)
		ret = bbox_ring_read(bbox, data_info);
	else
		ret = bbox_record_read(bbox, data_info);

	return ret;
}

void
bbox_set_record_desc(unsigned int bbox_id, unsigned int slot, const char *desc)
{
	struct bbox_info *bbox;
	struct record_info *r_info;
	unsigned long flags;

	bbox = get_bbox(bbox_id);
	if (!bbox)
		return;

	if (bbox_type(bbox) != BBOX_TYPE_RECORD)
		return;

	bbox_lock(bbox, &flags);
	if (slot < bbox->records.cnt) {
		r_info = &bbox->records.arr[slot];
		r_info->desc[BBOX_RECORD_DESC_LEN - 1] = 0;
		if (desc)
			strncpy(r_info->desc, desc, BBOX_RECORD_DESC_LEN - 1);
		else
			strcpy(r_info->desc, " ");
	}
	bbox_unlock(bbox, flags);
}

int bbox_alloc_record_slot(unsigned int bbox_id, unsigned int size,
		unsigned int type)
{
	struct bbox_info *bbox;
	struct record_info *r_info;
	unsigned long flags;
	int slot = -EINVAL;

	bbox = get_bbox(bbox_id);
	if (!bbox)
		return slot;

	if (bbox_type(bbox) != BBOX_TYPE_RECORD)
		return slot;

	bbox_lock(bbox, &flags);

	slot = -ENOSPC;
	if (avail_size(bbox) < (size + sizeof(struct record_info)))
		goto out;

	slot = bbox->records.cnt;
	r_info = &bbox->records.arr[slot];
	r_info->start = bbox_record_top(bbox) - size;
	r_info->size = size;
	r_info->type = type;
	r_info->mtime.tv_sec = 0;
	r_info->mtime.tv_nsec = 0;
	r_info->cpu = -1;
	r_info->pid = -1;
	r_info->state = -1;
	r_info->tsk_comm[0] = '\0';
	r_info->desc[0] = 0;

	bbox->data_base += sizeof(struct record_info);
	bbox->records.cnt++;
out:
	bbox_unlock(bbox, flags);
	return slot;
}

static inline void bbox_record_clear_one(struct bbox_info *bbox,
		unsigned int slot)
{
	struct record_info *r_info;

	if (slot >= bbox->records.cnt)
		return;

	r_info = &bbox->records.arr[slot];
	r_info->mtime.tv_sec = 0;
	r_info->mtime.tv_nsec = 0;
}

static void bbox_record_clear_all(struct bbox_info *bbox)
{
	int i;

	for (i = 0; i < bbox->records.cnt; i++)
		bbox_record_clear_one(bbox, i);
}

void bbox_record_clear(unsigned int bbox_id, int slot_id)
{
	unsigned long flags;
	struct bbox_info *bbox = get_bbox(bbox_id);

	if (!bbox)
		return;

	bbox_lock(bbox, &flags);
	if (slot_id < 0)
		bbox_record_clear_all(bbox);
	else
		bbox_record_clear_one(bbox, slot_id);
	bbox_unlock(bbox, flags);
}

static void bbox_setup(struct bbox_info *bbox,
		const char *name, int flags, int size)
{
	bbox->magic = BBOX_BUFF_MAGIC;
	bbox->name[BBOX_NAME_LEN - 1] = '\0';
	if (name)
		strncpy(bbox->name, name, BBOX_NAME_LEN - 1);
	else
		strncpy(bbox->name, "bbox", BBOX_NAME_LEN - 1);

	/* set flags first, then bbox_type() below can work */
	bbox->flags = flags;

	if (bbox_type(bbox) == BBOX_TYPE_RING) {
		bbox->data_base = bbox + 1;
		bbox->ringbuf.write_ptr = bbox->data_base;
		bbox->ringbuf.read_ptr = bbox->data_base;
	} else {
		bbox->records.cnt = 0;
		bbox->data_base = bbox->records.arr;
	}

	bbox->data_end = (void *)bbox + size;
	spin_lock_init(&bbox->lock);
}

int bbox_alloc(const char *name, int flags)
{
	struct bbox_info *bbox;
	unsigned int bbox_id;

	spin_lock(&bbox_alloc_lock);

	bbox_id = find_next_zero_bit(bbox_map, bbox_max_id, bbox_latest_id);
	if (bbox_id >= bbox_max_id)
		bbox_id = find_first_zero_bit(bbox_map, bbox_max_id);

	if (bbox_id >= bbox_max_id) {
		spin_unlock(&bbox_alloc_lock);
		return -ENOSPC;
	}

	set_bit(bbox_id, bbox_map);
	bbox_latest_id = bbox_id;
	spin_unlock(&bbox_alloc_lock);

	bbox = get_bbox(bbox_id);
	if (!bbox) {
		/* should never be here */
		WARN_ONCE(true, "bbox_buffer was NULL, id %d\n", bbox_id);
		return -EFAULT;
	}

	bbox_setup(bbox, name, flags, BBOX_SIZE);
	return bbox_id;
}

void bbox_update_name(unsigned int bbox_id, const char *name)
{
	struct bbox_info *bbox = get_bbox(bbox_id);
	unsigned long flags;

	if (!bbox || !name)
		return;

	bbox_lock(bbox, &flags);
	memset(bbox->name, 0, BBOX_NAME_LEN);
	strncpy(bbox->name, name, BBOX_NAME_LEN - 1);
	bbox_unlock(bbox, flags);
}

void bbox_free(unsigned int bbox_id)
{
	if (bbox_id < bbox_max_id)
		clear_bit(bbox_id, bbox_map);
	else {
		unsigned int idx = bbox_id_to_dyn_idx(bbox_id);
		struct bbox_info *bbox;

		if (!bbox_dyn_map || idx >= bbox_dynamic_max)
			return;

		spin_lock(&bbox_alloc_lock);
		bbox = get_bbox(bbox_id);
		if (!bbox) {
			spin_unlock(&bbox_alloc_lock);
			return;
		}

		clear_bit(idx, bbox_dyn_map);
		radix_tree_delete(&bbox_dynamic_tree, idx);
		spin_unlock(&bbox_alloc_lock);
		vfree(bbox);
	}
}

int bbox_alloc_dynamic(const char *name, int flags, unsigned int pages)
{
	int idx, ret;
	struct bbox_info *bbox;
	unsigned int size = pages << PAGE_SHIFT;

	bbox = vmalloc(size);
	if (!bbox)
		return -ENOMEM;

	spin_lock(&bbox_alloc_lock);
	idx = find_next_zero_bit(bbox_dyn_map, bbox_dynamic_max,
			bbox_dynamic_start);
	if (idx >= bbox_dynamic_max)
		idx = find_first_zero_bit(bbox_dyn_map, bbox_dynamic_max);
	if (idx >= bbox_dynamic_max) {
		spin_unlock(&bbox_alloc_lock);
		vfree(bbox);
		return -ENOSPC;
	}

	ret = radix_tree_insert(&bbox_dynamic_tree, idx, bbox);
	if (ret) {
		spin_unlock(&bbox_alloc_lock);
		vfree(bbox);
		return ret;
	}

	set_bit(idx, bbox_dyn_map);
	bbox_dynamic_start = idx;
	spin_unlock(&bbox_alloc_lock);

	bbox_setup(bbox, name, flags, size);
	return dyn_idx_to_bbox_id(idx);
}

static void free_dynamic_bbox(void)
{
	int idx = 0;

	if (!bbox_dyn_map)
		return;

	idx = find_first_bit(bbox_dyn_map, bbox_dynamic_max);
	while (idx < bbox_dynamic_max) {
		bbox_free(dyn_idx_to_bbox_id(idx));
		idx = find_next_bit(bbox_dyn_map, bbox_dynamic_max, idx);
	}
}

/* just think it stores raw strings. */
static int bbox_ring_show_content(struct seq_file *seq, struct bbox_info *bbox)
{
	char buf[128];
	int ret, i;
	struct bbox_data_info data;

	data.data = buf;
	data.size = 128;

	while (1) {
		ret = bbox_ring_read(bbox, &data);
		if (ret <= 0)
			break;

		for (i = 0; i < ret; i++)
			seq_printf(seq, "%c", buf[i]);
	}
	return 0;
}

int bbox_ring_show(struct seq_file *seq, unsigned int bbox_id)
{
	struct bbox_info *bbox = get_bbox(bbox_id);

	if (!seq || !bbox)
		return -EINVAL;

	return bbox_ring_show_content(seq, bbox);
}

static void bbox_show_time(struct seq_file *seq, struct timespec64 *ts)
{
	struct rtc_time tm;
	unsigned long local_time;

	local_time = (unsigned long)(ts->tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);
	seq_printf(seq, "\n[%04d-%02d-%02d %02d:%02d:%02d.%ld]\n",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec, ts->tv_nsec);
}

static int bbox_record_show_one(struct seq_file *seq,
		struct bbox_info *bbox, unsigned int slot)
{
	struct record_info *r_info;
	struct bbox_data_info data;
	void *buf;
	int ret;

	if (slot >= bbox->records.cnt)
		return -EINVAL;

	r_info = &bbox->records.arr[slot];
	/*no data had been written, ignore*/
	if (!r_info->mtime.tv_sec)
		return 0;

	buf = kmalloc(r_info->size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	data.data = buf;
	data.slot = slot;
	data.size = r_info->size;
	ret = bbox_record_read(bbox, &data);
	if (ret <= 0) {
		kfree(buf);
		return 0;
	}

	bbox_show_time(seq, &data.mtime);

	switch (r_info->type) {
	case BBOX_DATA_TYPE_STRING:
		seq_printf(seq, "%s\n", (char *)buf);
		break;
	case BBOX_DATA_TYPE_TRACE:
		seq_printf(seq,
				"CPU: %d PID: %d state %d comm: %s %s Call Trace:\n",
				r_info->cpu, r_info->pid, r_info->state,
				r_info->tsk_comm, r_info->desc);
		while (ret > 0) {
			void *ptr = *(void **)buf;

			if (ptr)
				seq_printf(seq, "%pS\n", ptr);
			buf += sizeof(void *);
			ret -= sizeof(void *);
		}
		break;
	case BBOX_DATA_TYPE_DATA:
		seq_printf(seq, "%d bytes data:\n", ret);
		while (ret > 0) {
			seq_printf(seq, "%lx\n", *(unsigned long *)buf);
			buf += sizeof(long);
			ret -= sizeof(long);
		}
		break;
	default:
		break;
	}

	kfree(data.data);
	return 0;
}

static int bbox_record_show_all(struct seq_file *seq, struct bbox_info *bbox)
{
	int i;

	seq_printf(seq, "[%s] capacity: %d\n", bbox->name, bbox->records.cnt);

	for (i = 0; i < bbox->records.cnt; i++) {
		bbox_record_show_one(seq, bbox, i);
		cond_resched();
	}

	return 0;
}

int bbox_record_show(struct seq_file *seq, unsigned int bbox_id, int slot_id)
{
	struct bbox_info *bbox = get_bbox(bbox_id);

	if (!seq || !bbox)
		return -EINVAL;

	if (slot_id < 0)
		return bbox_record_show_all(seq, bbox);
	else
		return bbox_record_show_one(seq, bbox, slot_id);
}

static int bbox_seq_show(struct seq_file *seq, void *v)
{
	struct bbox_info *bbox = v;

	seq_printf(seq, "Bbox %s:\n", bbox->name);

	if (bbox_type(bbox) == BBOX_TYPE_RING)
		bbox_ring_show_content(seq, bbox);
	else
		bbox_record_show_all(seq, bbox);

	seq_puts(seq, "\n");
	return 0;
}

static void *bbox_seq_start(struct seq_file *seq, loff_t *pos)
{
	*pos = find_next_bit(bbox_map, bbox_max_id, *pos);
	return get_bbox(*pos);
}

static void *bbox_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	*pos = find_next_bit(bbox_map, bbox_max_id, *pos + 1);
	return get_bbox(*pos);
}

static void bbox_seq_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations bbox_seq_ops = {
	.start	= bbox_seq_start,
	.next	= bbox_seq_next,
	.stop	= bbox_seq_stop,
	.show	= bbox_seq_show,
};

static int bbox_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &bbox_seq_ops);
}

const struct file_operations proc_bbox_operations = {
	.open    = bbox_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

int sysak_bbox_init(void)
{
	void *addr;
	unsigned int nlongs;

	bbox_max_id = bbox_total_size / BBOX_SIZE;
	bbox_total_size = bbox_max_id * BBOX_SIZE;
	if (!bbox_total_size)
		return -EINVAL;

	nlongs = BITS_TO_LONGS(bbox_max_id);
	bbox_map = kzalloc(sizeof(long) * nlongs, GFP_KERNEL);
	if (!bbox_map)
		return -ENOMEM;

	addr = vmalloc(bbox_total_size);
	if (!addr) {
		kfree(bbox_map);
		return -ENOMEM;
	}

	bbox_vmalloc_base = addr;

	bbox_dynamic_max = bbox_max_id * 100;
	nlongs = BITS_TO_LONGS(bbox_dynamic_max);
	bbox_dyn_map = kzalloc(sizeof(long) * nlongs, GFP_KERNEL);
	if (!bbox_dyn_map)
		printk(KERN_INFO "dynamic bbox is disabled\n");

	sysak_proc_create("bbox", &proc_bbox_operations);
	printk(KERN_INFO "pre-alloc %dB for blackbox\n", bbox_total_size);
	return 0;
}

void sysak_bbox_exit(void)
{
	free_dynamic_bbox();
	if (bbox_dyn_map)
		kfree(bbox_dyn_map);
	vfree(bbox_vmalloc_base);
}
