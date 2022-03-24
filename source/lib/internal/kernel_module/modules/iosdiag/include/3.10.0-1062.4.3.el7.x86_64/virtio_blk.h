#ifndef _VIRTIO_BLK_H
#define _VIRTIO_BLK_H

#include <linux/spinlock.h>
#include <linux/blk-mq.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/rh_kabi.h>
#include "iosdiag.h"

#define VQ_NAME_LEN 16

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

struct virtio_blk {
	struct virtio_device *vdev;

	/* The disk structure for the kernel. */
	struct gendisk *disk;

	/* Block layer tags. */
	struct blk_mq_tag_set tag_set;

	/* Process context for config space updates */
	struct work_struct config_work;

	/* What host tells us, plus 2 for header & tailer. */
	unsigned int sg_elems;

	/* Ida index - used to track minor number allocations. */
	int index;

	/* num of vqs */
	int num_vqs;
	struct virtio_blk_vq *vqs;
};

struct virtblk_req {
	struct request *req;
	struct virtio_blk_outhdr out_hdr;
	struct virtio_scsi_inhdr in_hdr;
	u8 status;
	struct scatterlist sg[];
};

struct vring_desc_state {
	void *data;			/* Data for callback. */
	struct vring_desc *indir_desc;	/* Indirect descriptor, if any. */
};

struct vring_virtqueue {
	struct virtqueue vq;

	/* Actual memory layout for this queue */
	struct vring vring;

	/* Can we use weak barriers? */
	bool weak_barriers;

	/* Other side has made a mess, don't try any more. */
	bool broken;

	/* Host supports indirect buffers */
	bool indirect;

	/* Host publishes avail event idx */
	bool event;

	/* Head of free buffer list. */
	unsigned int free_head;
	/* Number we've added since last sync. */
	unsigned int num_added;

	/* Last used index we've seen. */
	u16 last_used_idx;

	/* How to notify other side. FIXME: commonalize hcalls! */
	bool (*notify)(struct virtqueue *vq);

	/* DMA, allocation, and size information */
	bool we_own_ring;
	size_t queue_size_in_bytes;
	dma_addr_t queue_dma_addr;

#ifdef DEBUG
	/* They're supposed to lock for us. */
	unsigned int in_use;

	/* Figure out if their kicks are too delayed. */
	bool last_add_time_valid;
	ktime_t last_add_time;
#endif

	/* Per-descriptor state. */
	struct vring_desc_state desc_state[];
};
#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

struct blk_mq_ctx {
	struct {
		spinlock_t		lock;
		struct list_head	rq_list;
	}  ____cacheline_aligned_in_smp;

	unsigned int		cpu;
	unsigned int		index_hw;

	RH_KABI_DEPRECATE(unsigned int, ipi_redirect)

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];
	unsigned long		rq_merged;

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];

	struct request_queue	*queue;
	struct kobject		kobj;
} ____cacheline_aligned_in_smp;

static inline struct blk_mq_hw_ctx *blk_mq_map_queue(struct request_queue *q,
		int cpu)
{
	return q->queue_hw_ctx[q->mq_map[cpu]];
}

static inline struct blk_mq_hw_ctx *blk_mq_get_hctx_byrq(struct request *rq)
{
	return blk_mq_map_queue(rq->q, rq->mq_ctx->cpu);
}

static inline struct request *desc_state_data_to_req(struct virtqueue *vq, int head)
{
	void *data = to_vvq(vq)->desc_state[head].data;
	return data ? ((struct virtblk_req *)data)->req : NULL;
}

static inline int get_rq_internal_tag(struct request *rq)
{
	return -1;
}

static inline unsigned long get_issue_driver_ns(struct request *rq)
{
	if (!rq)
		return 0;
	if (rq->io_start_time_ns)
		return rq->io_start_time_ns;
	if (rq->timeout)
		return jiffies_to_usecs(rq->deadline - rq->timeout) * 1000;
	return 0;
}

static inline u64 get_check_hang_time_ns(void)
{
	return sched_clock();
}

typedef void (*blk_mq_rq_iter)(struct request *, void *, bool);
static inline int iter_all_rq(struct request_queue *q, blk_mq_rq_iter fn, void *data)
{
	blk_mq_tagset_busy_iter(q->tag_set, fn, data);
	return 0;
}

void get_vq_info(struct vq_info *vq_i, struct request *rq);
#endif

