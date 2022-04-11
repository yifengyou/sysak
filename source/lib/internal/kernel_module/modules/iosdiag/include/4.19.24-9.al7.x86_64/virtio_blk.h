#ifndef _VIRTIO_BLK_H
#define _VIRTIO_BLK_H

#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/blk-mq.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <scsi/scsi_cmnd.h>
#include "iosdiag.h"

#define VQ_NAME_LEN	16

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

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

	/* Last written value to avail->flags */
	u16 avail_flags_shadow;

	/* Last written value to avail->idx in guest byte order */
	u16 avail_idx_shadow;

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
#ifdef CONFIG_VIRTIO_BLK_SCSI
	struct scsi_request sreq;	/* for SCSI passthrough, must be first */
	u8 sense[SCSI_SENSE_BUFFERSIZE];
	struct virtio_scsi_inhdr in_hdr;
#endif
	struct virtio_blk_outhdr out_hdr;
	u8 status;
	struct scatterlist sg[];
};
#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

struct blk_mq_ctx {
	struct {
		spinlock_t		lock;
		struct list_head	rq_list;
	}  ____cacheline_aligned_in_smp;

	unsigned int		cpu;
	unsigned int		index_hw;

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];
	unsigned long		rq_merged;

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];

	struct request_queue	*queue;
	struct kobject		kobj;
} ____cacheline_aligned_in_smp;

struct blk_flush_queue {
	unsigned int		flush_queue_delayed:1;
	unsigned int		flush_pending_idx:1;
	unsigned int		flush_running_idx:1;
	unsigned long		flush_pending_since;
	struct list_head	flush_queue[2];
	struct list_head	flush_data_in_flight;
	struct request		*flush_rq;

	/*
	 * flush_rq shares tag with this rq, both can't be active
	 * at the same time
	 */
	struct request		*orig_rq;
	spinlock_t		mq_flush_lock;
};

static inline int enable_detect_flush_rq(void)
{
	return 0;
}

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
	return data ? blk_mq_rq_from_pdu(data) : NULL;
}

static inline int get_rq_internal_tag(struct request *rq)
{
	return rq ? rq->internal_tag : -1;
}

static inline unsigned long get_issue_driver_ns(struct request *rq)
{
	if (!rq)
		return 0;
	if (rq->io_start_time_ns)
		return rq->io_start_time_ns;
	if (rq->__deadline > rq->timeout)
		return jiffies_to_usecs(rq->__deadline - rq->timeout) * 1000;
	return 0;
}

/*
 * LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
 */
static inline u64 get_check_hang_time_ns(void)
{
	return ktime_get_ns();
}

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
extern fn_queue_tag_busy_iter sym_blk_mq_queue_tag_busy_iter;
//#endif
typedef void (*blk_mq_rq_iter)(struct request *, void *, bool);
static blk_mq_rq_iter fn_blk_mq_check_hang = NULL;
static void blk_mq_check_rq_hang(struct blk_mq_hw_ctx *hctx,
		struct request *rq, void *priv, bool reserved)
{
	if (fn_blk_mq_check_hang)
		fn_blk_mq_check_hang(rq, priv, reserved);
}

static inline int iter_all_rq(struct request_queue *q, blk_mq_rq_iter fn, void *data)
{
	fn_blk_mq_check_hang = fn;
	sym_blk_mq_queue_tag_busy_iter(q, blk_mq_check_rq_hang, data);
	return 0;
}
void get_vq_info(struct vq_info *vq_i, struct request *rq);
#endif
