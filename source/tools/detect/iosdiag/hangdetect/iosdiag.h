#ifndef __IOSDIAG_H
#define __IOSDIAG_H

#define MAX_STORE_RQ_CNT	128
#define MAX_FILE_NAME_LEN	255
#define BIO_INFO_MAX_PAGES	32
#define MAX_REQ_BIOS		32
#define TASK_COMM_LEN		16

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

/*
struct file_info {
	//unsigned long page_addr;
	//unsigned long i_ino;
	char name[MAX_FILE_NAME_LEN];
};
*/
struct bio_info {
	unsigned long bio_addr;
	unsigned long sector;
	unsigned int size;
	unsigned int pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILE_NAME_LEN];
	//struct file_info file[BIO_INFO_MAX_PAGES];
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
	//int errors;
	//unsigned long cmd_flags;
	char diskname[32];
	//struct bio_info bio[MAX_REQ_BIOS];
	struct bio_info first_bio;
};
#endif

