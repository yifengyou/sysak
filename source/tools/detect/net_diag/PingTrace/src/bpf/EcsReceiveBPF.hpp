#ifndef ECS_RECEIVE_BPF_H
#define ECS_RECEIVE_BPF_H

#include "bpf/eBPFProg.h"
#include "bpf_prog/ecs_receiver.skel.h"
#include "common/common.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {

class EcsReceiverBPF : public ReceiverBPF {
	struct ecs_receiver_bpf *receiver;
	int map_fd;

public:
	EcsReceiverBPF(options *opt)
	{
		BPF_SKELETON_INIT(ecs_receiver_bpf, receiver, opt);
		map_fd = bpf_map__fd(receiver->maps.pt_map);
	}
	~EcsReceiverBPF()
	{
		ecs_receiver_bpf__destroy(receiver);
	}
	eBPFResult query_tx_points(pingtrace_map_key *key)
	{
		return eBPFResult::from(map_fd, key);
	}
};
} // namespace pingtrace
#endif