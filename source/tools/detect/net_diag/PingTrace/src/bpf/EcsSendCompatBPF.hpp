#ifndef ECS_SEND_COMPAT_BPF_H
#define ECS_SEND_COMPAT_BPF_H

#include "bpf/eBPFCompat.hpp"
#include "bpf/eBPFProg.h"
#include "bpf/eBPFResult.h"
#include "bpf_prog/ecs_sender_compat.skel.h"
#include "common/common.h"
#include "common/options.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {
class EcsSenderCompatBPF : public EcsSenderBPFBase {
	struct ecs_sender_compat_bpf *sender;
	int sched_map;
	int tx_map;
	int rx_map;
	int irq_map;
	int id_map;

	void init_sched_map()
	{
		uint64_t pid = getpid();
		uint32_t idx = PT_SCHED_PID;
		bpf_map_update_elem(sched_map, &idx, &pid, 0);
	}

	void try_to_shrink_map()
	{
		uint32_t flag = eBPFCompat::get_full_flag(id_map);

		if (!flag)
			return;
		eBPFCompat::clear_map(tx_map);
		eBPFCompat::clear_map(rx_map);
		eBPFCompat::clear_full_flag(id_map);
	}

public:
	EcsSenderCompatBPF(options *opt, uint32_t id)
	{
		BPF_SKELETON_INIT(ecs_sender_compat_bpf, sender, opt);
		tx_map = bpf_map__fd(sender->maps.tx_map);
		rx_map = bpf_map__fd(sender->maps.rx_map);
		sched_map = bpf_map__fd(sender->maps.sched_map);
		irq_map = bpf_map__fd(sender->maps.irq_map);
		id_map = bpf_map__fd(sender->maps.id_map);
		init_sched_map();
		eBPFCompat::set_filter_id(id_map, id);
	}

	~EcsSenderCompatBPF()
	{
		ecs_sender_compat_bpf__destroy(sender);
	}

	uint64_t query_sched_time()
	{
		uint64_t ts;
		int idx = PT_SCHED_TS;
		bpf_map_lookup_elem(sched_map, &idx, &ts);
		return ts;
	}

	void clear_recorded_sched_time()
	{
		uint64_t ts = 0;
		int idx = PT_SCHED_TS;
		bpf_map_update_elem(sched_map, &idx, &ts, 0);
	}

	eBPFResult query_tx_points(pingtrace_map_key *key)
	{
		auto res = eBPFResult::from(tx_map, key);
		bpf_map_delete_elem(tx_map, key);
		try_to_shrink_map();
		return res;
	}

	eBPFResult query_rx_points(pingtrace_map_key *key)
	{
		auto res = eBPFResult::from(rx_map, key);
		bpf_map_delete_elem(rx_map, key);
		try_to_shrink_map();
		return res;
	}
};
} // namespace pingtrace

#endif // ECS_SEND_COMPAT_BPF_H