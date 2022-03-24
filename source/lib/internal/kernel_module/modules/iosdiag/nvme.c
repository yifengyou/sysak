
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/nvme.h>
#include <nvme.h>
#include <virtio_blk.h>

static struct nvme_queue *get_nvme_queue_by_rq(struct request *rq)
{
	struct blk_mq_hw_ctx *hctx;

	if (!rq)
		return NULL;

	hctx = blk_mq_get_hctx_byrq(rq);
	if (!hctx)
		return NULL;
	return hctx->driver_data ? hctx->driver_data : NULL;
}

static int get_cq_end(struct nvme_queue *nvmeq, struct request *rq)
{
	int head = nvmeq->cq_head;

	do {
		if (nvmeq->cqes[head].command_id == -1)
			return head;
	} while (++head < nvmeq->q_depth);
	return -1;
}

static int get_cq_rq_idx(struct nvme_queue *nvmeq, struct request *rq)
{
	int head = 0;

	do {
		if (nvmeq->cqes[head].command_id == rq->tag)
			return head;
	} while (++head < nvmeq->q_depth);
	return -1;
}

void get_nvme_info(struct nvme_info *nvme_i, struct request *rq)
{
	struct nvme_queue *nvmeq;

	if (!(nvmeq = get_nvme_queue_by_rq(rq)))
		return;

	nvme_i->qid = nvmeq->qid;
	nvme_i->q_depth = nvmeq->q_depth;
	nvme_i->cq_head = nvmeq->cq_head;
	nvme_i->cq_end = get_cq_end(nvmeq, rq);
	nvme_i->cq_rq_idx = get_cq_rq_idx(nvmeq, rq);
	nvme_i->sq_tail = nvmeq->sq_tail;
	nvme_i->sq_rq_idx = get_sq_rq_idx(nvmeq, rq);
	nvme_i->sq_last_db = readl(nvmeq->q_db);
	nvme_i->cmd_ctx = get_cmd_ctx(nvmeq, rq);
}

