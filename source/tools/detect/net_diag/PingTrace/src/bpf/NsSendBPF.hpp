#ifndef NS_SEND_BPF_H
#define NS_SEND_BPF_H

#include "bpf/eBPFProg.h"
#include "bpf_prog/ns_sender.skel.h"
#include "common/common.h"
#include "common/options.hpp"
#include "bpf/eBPFResult.h"
#include "pt/Packet.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {
class NsSenderBPF {
	struct ns_sender_bpf *receiver;
	int tx_map;
	int rx_map;

public:
	NsSenderBPF(options *opt)
	{
		BPF_SKELETON_INIT(ns_sender_bpf, receiver, opt);
		tx_map = bpf_map__fd(receiver->maps.tx_map);
		rx_map = bpf_map__fd(receiver->maps.rx_map);
	}
	~NsSenderBPF()
	{
		ns_sender_bpf__destroy(receiver);
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