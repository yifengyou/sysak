#ifndef ECS_SEND_BPF_H
#define ECS_SEND_BPF_H

#include "bpf/eBPFProg.h"
#include "bpf_prog/ecs_sender.skel.h"
#include "common/common.h"
#include "common/options.hpp"
#include "bpf/eBPFResult.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {
class EcsSenderBPF : public EcsSenderBPFBase{
	struct ecs_sender_bpf *sender;
	int sched_map;
	int tx_map;
	int rx_map;
	int irq_map;

	void init_sched_map()
	{
		uint64_t pid = getpid();
		uint32_t idx = PT_SCHED_PID;
		bpf_map_update_elem(sched_map, &idx, &pid, 0);
	}

public:
	EcsSenderBPF(options *opt)
	{
		BPF_SKELETON_INIT(ecs_sender_bpf, sender, opt);
		tx_map = bpf_map__fd(sender->maps.tx_map);
		rx_map = bpf_map__fd(sender->maps.rx_map);
		sched_map = bpf_map__fd(sender->maps.sched_map);
		irq_map = bpf_map__fd(sender->maps.irq_map);
		init_sched_map();
	}

	~EcsSenderBPF()
	{
		ecs_sender_bpf__destroy(sender);
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
		return eBPFResult::from(tx_map, key);
	}

	eBPFResult query_rx_points(pingtrace_map_key *key)
	{
		return eBPFResult::from(rx_map, key);
	}
};
} // namespace pingtrace
#endif