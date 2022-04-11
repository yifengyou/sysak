#ifndef _NVME_H
#define _NVME_H

#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/blk-mq.h>
#include <linux/nvme.h>
#include <linux/kthread.h>
#include "iosdiag.h"

struct nvme_queue {
	struct device *q_dmadev;
	void *nvme_dev; //struct nvme_dev *dev;
	spinlock_t sq_lock;
	struct nvme_command *sq_cmds;
	struct nvme_command __iomem *sq_cmds_io;
	spinlock_t cq_lock ____cacheline_aligned_in_smp;
	volatile struct nvme_completion *cqes;
	struct blk_mq_tags **tags;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	u32 __iomem *q_db;
	u16 q_depth;
	s16 cq_vector;
	u16 sq_tail;
	u16 cq_head;
	u16 last_cq_head;
	u16 qid;
	u8 cq_phase;
	u32 *dbbuf_sq_db;
	u32 *dbbuf_cq_db;
	u32 *dbbuf_sq_ei;
	u32 *dbbuf_cq_ei;
};

static int get_sq_rq_idx(struct nvme_queue *nvmeq, struct request *rq)
{
	int tail = nvmeq->sq_tail;
	struct nvme_command cmd;

	do {
		if (nvmeq->sq_cmds_io) {
			memcpy_toio(&cmd, &nvmeq->sq_cmds_io[tail], sizeof(struct nvme_command));
			if (cmd.common.command_id == rq->tag)
				return tail;
		}
		else if (nvmeq->sq_cmds[tail].common.command_id == rq->tag)
			return tail;
	} while (--tail >= 0);
	return -1;
}

static unsigned long get_cmd_ctx(struct nvme_queue *nvmeq, struct request *rq)
{
	//struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	return 0;
}
#endif
