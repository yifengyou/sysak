#include "bpf_iosdiag_common.h"

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

