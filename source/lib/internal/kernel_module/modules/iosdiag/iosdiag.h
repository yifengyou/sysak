#ifndef __IOSDIAG_H
#define __IOSDIAG_H
#include <linux/blkdev.h>
#include <linux/fs.h>

#define MAX_STORE_RQ_CNT	128
#define MAX_FILE_NAME_LEN	255
#define BIO_INFO_MAX_PAGES	32
#define MAX_REQ_BIOS		32

enum disk_type {
	DISK_VIRTIO_BLK,
	DISK_NVME,
	DISK_SCSI,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
enum rq_atomic_flags {
	REQ_ATOM_COMPLETE = 0,
	REQ_ATOM_STARTED,
};
#endif
/*
struct rq_buffer {
	struct request rq;
	unsigned long long check_time_ns;
	void *rq_addr;
};
*/
struct vq_info {
	int qid;
	int vring_num;
	int last_used_idx;
	int used_idx;
	int used_ring_flags;
	int last_avail_idx;
	int avail_idx;
	int avail_ring_flags;
	int event;
	int rq_avail_idx;
	int last_kick_avail_idx;
	int rq_used_idx;
};

struct nvme_info {
	int qid;
	int q_depth; //sq/cq depth
	int cq_head; //nvmeq->cqes[cq_head]~nvmeq->cqes[cq_end], including req->tag?
	int cq_end;
	int cq_rq_idx; //rq idx in cq
	//int last_cq_head; //nvmeq->sq_head or nvmeq->last_cq_head
	int sq_tail; //0~nvmeq->sq_cmds[idx].command_id, including req->tag?
	int sq_rq_idx; //rq idx in sq
	int sq_last_db; //last sq idx host kick nvme, nvmeq->q_db
	unsigned long cmd_ctx;
};

struct scsi_info {
	int done_hander_defined;
	int is_mq;
};

struct bio_info {
	unsigned long bio_addr;
	unsigned long sector;
	unsigned int size;
	unsigned int pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILE_NAME_LEN];
};

struct rq_hang_info {
	unsigned int data_len;
	unsigned long sector;
	unsigned long req_addr;
	unsigned long long io_start_ns;
	unsigned long long io_issue_driver_ns;
	unsigned long long check_hang_ns;
	char op[64];
	char state[16];
	struct vq_info vq;
	struct nvme_info nvme;
	struct scsi_info scsi;
	int tag;
	int internal_tag;
	int cpu;
	char diskname[BDEVNAME_SIZE];
	//int errors;
	//unsigned long cmd_flags;
	struct bio_info first_bio;
};

typedef void (*fn_queue_tag_busy_iter)(struct request_queue *q, busy_iter_fn *fn, void *priv);
typedef struct files_struct *(*fn_get_files_struct)(struct task_struct *);
typedef void (*fn_put_files_struct)(struct files_struct *fs);

int fill_hang_info_from_rq(struct rq_hang_info *rq_hang_info,
			       struct request *rq,
			       int disk_type);
#endif

