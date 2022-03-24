
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/ctype.h>
#include <linux/genhd.h>
#include "iosdiag.h"
#include <virtio_blk.h>
#include <nvme.h>

struct req_op_name{
	int op;
	char *op_str;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define REQ_OP_NAME(name) {REQ_OP_##name, #name}
#else
#define REQ_READ	0
#define REQ_OP_NAME(name) {REQ_##name, #name}
#endif
static struct req_op_name g_op_name[] = {
	REQ_OP_NAME(READ),
	REQ_OP_NAME(WRITE),
	REQ_OP_NAME(FLUSH),
	REQ_OP_NAME(DISCARD),
	REQ_OP_NAME(WRITE_SAME),
};
#define SINGLE_OP_NAME_SIZE	16
#define MAX_OP_NAME_SIZE	((SINGLE_OP_NAME_SIZE + 1) * 5)

static const char *const blk_mq_rq_state_name_array[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	[REQ_ATOM_COMPLETE]	= "complete",
	[REQ_ATOM_STARTED]	= "in_flight",
#else
	[MQ_RQ_IDLE]		= "idle",
	[MQ_RQ_IN_FLIGHT]	= "in_flight",
	[MQ_RQ_COMPLETE]	= "complete",
#endif
};

extern fn_get_files_struct sym_get_files_struct;
extern fn_put_files_struct sym_put_files_struct;
extern int get_bio_file_info(void);
extern void get_scsi_info(struct scsi_info *scsi_i, struct request *rq);

static char *get_disk_name(struct gendisk *hd, int partno, char *buf)
{
	if (!partno)
		snprintf(buf, BDEVNAME_SIZE, "%s", hd->disk_name);
	else if (isdigit(hd->disk_name[strlen(hd->disk_name)-1]))
		snprintf(buf, BDEVNAME_SIZE, "%sp%d", hd->disk_name, partno);
	else
		snprintf(buf, BDEVNAME_SIZE, "%s%d", hd->disk_name, partno);
	return buf;
}

static void blk_rq_op_name(int op_flags, char *op_buf, int buf_len)
{
	int i = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	for (; i < (sizeof(g_op_name) / sizeof(g_op_name[0])); i++) {
		if (op_flags == g_op_name[i].op) {
			strcat(op_buf, g_op_name[i].op_str);
			return;
		}
	}
#else
	int len;
	for (; i < (sizeof(g_op_name) / sizeof(g_op_name[0])); i++) {
		if (op_flags & g_op_name[i].op) {
			if ((len = strlen(op_buf)) >= buf_len)
				return;
			if (len) {
				strncat(op_buf, "|", min((strlen("|") + 1),
							(buf_len - len)));
				op_buf[buf_len - 1] = '\0';
				if ((len = strlen(op_buf)) >= buf_len)
					return;
			}
			strncat(op_buf, g_op_name[i].op_str,
					min((strlen(g_op_name[i].op_str) + 1),
					    (buf_len - len)));
			op_buf[buf_len - 1] = '\0';
		}
	}
#endif
}

static const char *blk_mq_rq_state_name(unsigned int rq_state)
{
	if (WARN_ON_ONCE(rq_state >=
			 ARRAY_SIZE(blk_mq_rq_state_name_array)))
		return "(?)";
	return blk_mq_rq_state_name_array[rq_state];
}

static char *__dentry_name(struct dentry *dentry, char *name)
{
	char *p = dentry_path_raw(dentry, name, PATH_MAX);

	if (IS_ERR(p)) {
		__putname(name);
		return NULL;
	}

	if (p + strlen(p) + 1 != name + PATH_MAX) {
		__putname(name);
		return NULL;
	}

	if (p > name)
		strcpy(name, p);

	return name;
}

static char *dentry_name(struct dentry *dentry)
{
	char *name = __getname();
	if (!name)
		return NULL;

	return __dentry_name(dentry, name);
}

static char *inode_name(struct inode *ino)
{
	struct dentry *dentry;
	char *name;

	dentry = d_find_alias(ino);
	if (!dentry)
		return NULL;

	name = dentry_name(dentry);
	dput(dentry);
	return name;
}

static int is_task_open_file(struct task_struct *p, struct inode *ino)
{
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	unsigned int fd;

	files = sym_get_files_struct(p);
	if (files) {
		rcu_read_lock();
		fdt = files_fdtable(files);
		fd = find_first_bit(fdt->open_fds, fdt->max_fds);
		while (fd < fdt->max_fds) {
			file = fcheck_files(files, fd);
			if (file && (file_inode(file) == ino)) {
				rcu_read_unlock();
				sym_put_files_struct(files);
				return 1;
			}
			fd = find_next_bit(fdt->open_fds, fdt->max_fds, fd + 1);
		}
		rcu_read_unlock();
		sym_put_files_struct(files);
	}
	return 0;
}

static void get_task_info_lsof(struct inode *ino, unsigned int *pid,
			      char *comm)
{
	struct task_struct *p;

	rcu_read_lock();
	for_each_process(p) {
		if (p->flags & PF_KTHREAD)
			continue;
		rcu_read_unlock();
		get_task_struct(p);
		if (is_task_open_file(p, ino)) {
			*pid = p->pid;
			memcpy(comm, p->comm, sizeof(p->comm));
			put_task_struct(p);
			return;
		}
		put_task_struct(p);

		cond_resched();
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static int get_inode_filename(struct inode *ino, char *name_buf,
	int len)
{
	char *name;

	if (!ino->i_ino)
		return -1;

	name = inode_name(ino);
	if (name) {
		if (strlen(name) + 1 <= len)
			strlcpy(name_buf, name, strlen(name) + 1);
		else {
			strlcpy(name_buf, "...", 4);
			strlcpy(name_buf + 3,
				name + (strlen(name) + 1 - (len - 3)),
				(len - 3));
		}
		__putname(name);
		return 0;
	}
	return -1;
}

static void get_bio_info(struct bio_info *bio_i, struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	if (!bio)
		return;

	bio_i->bio_addr = (unsigned long)bio;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	bio_i->sector = bio->bi_iter.bi_sector;
	bio_i->size = bio->bi_iter.bi_size;
#else
	bio_i->sector = bio->bi_sector;
	bio_i->size = bio->bi_size;
#endif
	if (get_bio_file_info()) {
		bio_for_each_segment_all(bvec, bio, i) {
			struct page *page = bvec->bv_page;

			if (!page)
				continue;
			if (page->mapping && page->mapping->host) {
				if (get_inode_filename(page->mapping->host, bio_i->filename,
					sizeof(bio_i->filename))) {
					continue;
				}

				if (sym_get_files_struct && sym_put_files_struct)
					get_task_info_lsof(page->mapping->host, &bio_i->pid,
							   bio_i->comm);
				break;
			}
		}
	}
}

static void get_rq_info(struct rq_hang_info *rq_hi, struct request *rq)
{
	char op_buf[MAX_OP_NAME_SIZE];
	int op;

	rq_hi->data_len = rq->__data_len;
	rq_hi->sector = rq->__sector;
	strcpy(op_buf, "");
	//rq_hi->cmd_flags = rq->cmd_flags;
	//rq_hi->errors = rq->errors;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	//op = rq->cmd_flags & REQ_OP_MASK;
	op = req_op(rq);
	blk_rq_op_name(op, op_buf, sizeof(op_buf));
#else
	blk_rq_op_name(rq->cmd_flags, op_buf, sizeof(op_buf));
#endif
	strncpy(rq_hi->op, op_buf, min(strlen(op_buf), sizeof(rq_hi->op) - 1));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
	strcpy(rq_hi->state, (blk_mq_rq_state_name((test_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags) ?
			      REQ_ATOM_COMPLETE : REQ_ATOM_STARTED))));
#else
	strcpy(rq_hi->state, blk_mq_rq_state_name(READ_ONCE(rq->state)));
#endif
	rq_hi->tag = rq->tag;
	rq_hi->internal_tag = get_rq_internal_tag(rq);
	if (rq->mq_ctx)
		rq_hi->cpu = rq->mq_ctx->cpu;
	else
		rq_hi->cpu = rq->cpu;
	rq_hi->io_start_ns = rq->start_time_ns;
	rq_hi->io_issue_driver_ns = get_issue_driver_ns(rq);
	if (rq->rq_disk)
		get_disk_name(rq->rq_disk, rq->part ? rq->part->partno : 0,
			  rq_hi->diskname);
	get_bio_info(&rq_hi->first_bio, rq->bio);
}

int fill_hang_info_from_rq(struct rq_hang_info *rq_hi,
	struct request *rq, int disk_type)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
	if (!rq || !test_bit(REQ_ATOM_STARTED, &rq->atomic_flags))
		return -1;
#else
	if (!rq || !refcount_read(&rq->ref))
		return -1;
#endif
	get_rq_info(rq_hi, rq);
	if (disk_type == DISK_VIRTIO_BLK)
		get_vq_info(&rq_hi->vq, rq);
	else if (disk_type == DISK_NVME)
		get_nvme_info(&rq_hi->nvme, rq);
	else if (disk_type == DISK_SCSI)
		get_scsi_info(&rq_hi->scsi, rq);
	return 0;
}

