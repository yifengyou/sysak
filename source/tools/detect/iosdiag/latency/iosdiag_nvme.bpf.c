#include "bpf_iosdiag_common.h"

#if 1
SEC("kprobe/nvme_queue_rq")
int kprobe_nvme_queue_rq(struct pt_regs *ctx)
{
	struct blk_mq_queue_data *bd =
		(struct blk_mq_queue_data *)PT_REGS_PARM2(ctx);
	bool kick;
	struct request *req;

	bpf_probe_read(&kick, sizeof(bool), &bd->last);
	if (!kick)
		return 0;

	bpf_probe_read(&req, sizeof(struct request *), &bd->rq);
	if (!req) {
		bpf_printk("kprobe_nvme_queue_rq: con't get request");
		return 0;
	}
	return trace_io_driver_route(ctx, req, IO_ISSUE_DRIVER_POINT);
}

#else
static struct request *blk_mq_tag_to_rq(struct blk_mq_tags *tags, unsigned int tag)
{
	unsigned int nr_tags;
	struct request *rqs, *rq;

	bpf_probe_read(&nr_tags, sizeof(unsigned int), &tags->nr_tags);
	if (tag < nr_tags) {
		bpf_probe_read(&rqs, sizeof(struct request *), &tags->rqs);
		bpf_probe_read(&rq, sizeof(struct request *),
			       rqs + sizeof(struct request *) * tag);
		return rq;
	}
	return NULL;
}

SEC("kprobe/nvme_submit_cmd")
int kprobe_nvme_submit_cmd(struct pt_regs *ctx)
{
	struct nvme_queue *nvmeq = (struct nvme_queue *)PT_REGS_PARM1(ctx);
	void *nvme_cmd = (void *)PT_REGS_PARM2(ctx);
	bool kick = (bool)PT_REGS_PARM3(ctx);
	struct blk_mq_tags *tags;
	unsigned short tag;
	struct request *req;

	if (!kick)
		return;

	bpf_probe_read(&tags, sizeof(struct blk_mq_tags *), &nvmeq->tags);
	bpf_probe_read(&tags, sizeof(struct blk_mq_tags *), tags);
	bpf_probe_read(&tag, sizeof(unsigned short), (nvme_cmd + 2));

	req = blk_mq_tag_to_rq(tags, tag);
	if (!req) {
		bpf_printk("kprobe_nvme_submit_cmd: con't get request");
		return 0;
	}
	return trace_io_driver_route(ctx, req, IO_ISSUE_DEVICE_POINT);
}
#endif
SEC("kprobe/blk_mq_complete_request")
int kprobe_blk_mq_complete_request(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM1(ctx);

	if (!req) {
		bpf_printk("kprobe_blk_mq_complete_request: con't get request");
		return 0;
	}
	return trace_io_driver_route(ctx, req, IO_RESPONCE_DRIVER_POINT);
}
char _license[] SEC("license") = "GPL";

