
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <virtio_blk.h>

static struct virtqueue *get_virtqueue_by_rq(struct request *rq)
{
	struct virtio_blk *vblk;
	int qid;
	struct blk_mq_hw_ctx *hctx;

	if (!rq)
		return NULL;

	hctx = blk_mq_get_hctx_byrq(rq);
	if (!hctx)
		return NULL;
	qid = hctx->queue_num;
	vblk = hctx->queue->queuedata;
	if (qid >= vblk->num_vqs)
		return NULL;
	return vblk->vqs[qid].vq;
}

static struct vring *get_vring_by_vq(struct virtqueue *vq)
{
	return &to_vvq(vq)->vring;
}

static int get_vq_id(struct request *rq)
{
	struct blk_mq_hw_ctx *hctx;

	if (!rq)
		return -1;

	hctx = blk_mq_get_hctx_byrq(rq);
	if (!hctx)
		return -1;
	return hctx->queue_num;
}

static int get_rq_avail_idx(struct request *rq)
{
	int i;
	struct vring *vring;
	struct virtqueue *vq;
	u16 last_used_idx;
	u16 current_avail_idx;
	int head;
	void *data;

	if (!(vq = get_virtqueue_by_rq(rq)))
		return -1;
	vring = get_vring_by_vq(vq);
	current_avail_idx = vring->avail->idx;
	last_used_idx = to_vvq(vq)->last_used_idx;
	while (last_used_idx <= current_avail_idx) {
		i = last_used_idx & (vring->num - 1);
		head = virtio16_to_cpu(vq->vdev, vring->avail->ring[i]);
		if (head < vring->num)
			if (desc_state_data_to_req(vq, head) == rq)
				return last_used_idx;
		else
			return -1;
		last_used_idx++;
	}
	return -1;
}

static int get_rq_used_idx(struct request *rq)
{
	int i;
	struct vring *vring;
	struct virtqueue *vq;
	u16 last_used_idx;
	u16 used_idx;
	int head;
	void *data;

	if (!(vq = get_virtqueue_by_rq(rq)))
		return -1;
	vring = get_vring_by_vq(vq);
	used_idx = virtio16_to_cpu(vq->vdev, vring->used->idx);
	last_used_idx = to_vvq(vq)->last_used_idx;
	while (last_used_idx < used_idx) {
		i = last_used_idx & (vring->num - 1);
		head = virtio32_to_cpu(vq->vdev, vring->used->ring[i].id);
		if (head < vring->num)
			if (desc_state_data_to_req(vq, head) == rq)
				return last_used_idx;
		else
			return -1;
		last_used_idx++;
	}
	return -1;
}

void get_vq_info(struct vq_info *vq_i, struct request *rq)
{
	struct vring *vring;
	struct virtqueue *vq;

	if (!(vq = get_virtqueue_by_rq(rq)))
		return;
	vring = get_vring_by_vq(vq);

	vq_i->qid = get_vq_id(rq);
	vq_i->vring_num = vring->num;
	vq_i->event = to_vvq(vq)->event ? 1 : 0;
	vq_i->last_used_idx = to_vvq(vq)->last_used_idx;
	vq_i->used_idx = vring->used->idx;
	vq_i->used_ring_flags = vring->used->flags;
	if (vq_i->event == 1)
		vq_i->last_avail_idx =
			*(__virtio16 *)&vring->used->ring[vring->num];
	else
		vq_i->last_avail_idx = -1;
	vq_i->avail_idx = vring->avail->idx;
	vq_i->avail_ring_flags = vring->avail->flags;
	vq_i->last_kick_avail_idx = vq_i->avail_idx - to_vvq(vq)->num_added;
	vq_i->rq_avail_idx = get_rq_avail_idx(rq);
	vq_i->rq_used_idx = get_rq_used_idx(rq);
}

