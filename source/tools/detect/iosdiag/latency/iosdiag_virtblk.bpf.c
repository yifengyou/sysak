#include "bpf_iosdiag_common.h"

struct bpf_map_def SEC("maps") iosdiag_virtblk_maps = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(pid_t),
	.value_size = sizeof(unsigned long),
	.max_entries = 2048,
};

SEC("kprobe/virtio_queue_rq")
int kprobe_virtio_queue_rq(struct pt_regs *ctx)
{
	struct blk_mq_queue_data *bd =
		(struct blk_mq_queue_data *)PT_REGS_PARM2(ctx);
	bool kick;
	unsigned long req_addr;
	pid_t pid = bpf_get_current_pid_tgid();

	bpf_probe_read(&kick, sizeof(bool), &bd->last);
	if (!kick)
		return 0;

	bpf_probe_read(&req_addr, sizeof(struct request *), &bd->rq);
	if (!req_addr) {
		bpf_printk("kprobe_virtio_queue_rq: con't get request");
		return 0;
	}
	bpf_map_update_elem(&iosdiag_virtblk_maps, &pid, &req_addr, BPF_ANY);
	return 0;
}

SEC("kretprobe/virtio_queue_rq")
int kretprobe_virtio_queue_rq(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	unsigned long *req_addr;
	pid_t pid = bpf_get_current_pid_tgid();

	if (!ret) {
		req_addr = bpf_map_lookup_elem(&iosdiag_virtblk_maps, &pid);
		if (!req_addr || !(*req_addr))
			return 0;
		trace_io_driver_route(ctx, (struct request *)*req_addr, IO_ISSUE_DEVICE_POINT);
	}
	bpf_map_delete_elem(&iosdiag_virtblk_maps, &pid);
	return 0;
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

