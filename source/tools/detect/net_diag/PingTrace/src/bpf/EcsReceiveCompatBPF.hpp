#ifndef ECS_RECEIVE_COMPAT_BPF_H
#define ECS_RECEIVE_COMPAT_BPF_H

#include "bpf/eBPFCompat.hpp"
#include "bpf/eBPFProg.h"
#include "bpf_prog/ecs_receiver_compat.skel.h"
#include "common/common.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {

class EcsReceiverCompatBPF : public ReceiverBPF {
	struct ecs_receiver_compat_bpf *receiver;
	int pt_map;
	int id_map;

public:
	EcsReceiverCompatBPF(options *opt)
	{
		BPF_SKELETON_INIT(ecs_receiver_compat_bpf, receiver, opt);
		pt_map = bpf_map__fd(receiver->maps.pt_map);
		id_map = bpf_map__fd(receiver->maps.id_map);
		eBPFCompat::set_filter_id(id_map, -1);
		eBPFCompat::clear_full_flag(id_map);
	}

	~EcsReceiverCompatBPF()
	{
		ecs_receiver_compat_bpf__destroy(receiver);
	}

	void try_to_shrink_map()
	{
		uint32_t flag = eBPFCompat::get_full_flag(id_map);

		if (!flag)
			return;
		eBPFCompat::clear_map(pt_map);
		eBPFCompat::clear_full_flag(id_map);
	}

	eBPFResult query_tx_points(pingtrace_map_key *key)
	{
		auto res = eBPFResult::from(pt_map, key);
		bpf_map_delete_elem(pt_map, key);
		try_to_shrink_map();
		return res;
	}
};
} // namespace pingtrace
#endif