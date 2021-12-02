#ifndef NS_RECEIVE_BPF_H
#define NS_RECEIVE_BPF_H

#include "bpf/eBPFProg.h"
#include "bpf_prog/ns_receiver.skel.h"
#include "common/common.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {
class NsReceiverBPF: public ReceiverBPF {
	struct ns_receiver_bpf *receiver;
	int tx_map;
	int rx_map;

public:
	NsReceiverBPF(options *opt)
	{
		BPF_SKELETON_INIT(ns_receiver_bpf, receiver, opt);
		tx_map = bpf_map__fd(receiver->maps.tx_map);
		rx_map = bpf_map__fd(receiver->maps.rx_map);
	}
	~NsReceiverBPF()
	{
		ns_receiver_bpf__destroy(receiver);
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