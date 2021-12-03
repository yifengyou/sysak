#ifndef PINGTRACE_SERVER_H
#define PINGTRACE_SERVER_H

#include "bpf/EcsReceiveBPF.hpp"
#include "bpf/EcsReceiveCompatBPF.hpp"
#include "bpf/NsReceiveBPF.hpp"
#include "bpf/eBPFProg.h"
#include "display/TimeStampPoints.h"
#include "netmodel/NetModel.h"
#include "pt/Ping.hpp"
#include <memory>

namespace pingtrace {
class PingTraceServer : public PingTrace {
	void server_recv_pkt_modify(PingTracePacket &pkt)
	{
		uint16_t flags;
		flags = pkt.flags();
		flags |= PINGTRACE_F_DONTADD;
		pkt.set_flags(flags);
		pkt.set_icmp_type(ICMP_ECHOREPLY);
	}

public:
	int run(struct options *opt)
	{
		Ping ping(1 << ICMP_ECHO, false);
		sockaddr_in addr;
		int len;
		int i = 0;
		std::shared_ptr<ReceiverBPF> bpf;
		PingTracePacket pkt;
		bool native;
		uint16_t user_id;

		pkt.init(config::max_entry_num);
		set_signal_callback(opt->runtime);

		if (opt->is_namespace) {
			bpf = std::make_shared<NsReceiverBPF>(opt);
		} else {
			if (opt->compat) {
				bpf = std::make_shared<EcsReceiverCompatBPF>(opt);
			} else {
				bpf = std::make_shared<EcsReceiverBPF>(opt);
			}
		}

		while (!stop) {
			uint16_t flags;
			pingtrace_map_key key;

			len = pkt.buf_size = ping.recv((char *)(pkt.buf), pkt.buf_cap, &addr);
			if (len <= 0)
				continue;
			if (!pkt.unpack(ICMP_ECHO))
				continue;
			if (pkt.flags() & PINGTRACE_F_DONTADD)
				continue;
			server_recv_pkt_modify(pkt);

			usleep(2000); /* waiting for first pkt out */

			key.seq = pkt.seq();
			key.id = pkt.id();
			auto rx_ts = bpf->query_rx_points(&key);
			for (auto &ts : rx_ts.points()) {
				pkt.add_timestamp(ts, opt->user_id);
			}

			auto tx_ts = bpf->query_tx_points(&key);
			for (auto &ts : tx_ts.points()) {
				pkt.add_timestamp(ts, opt->user_id);
			}
			pkt.update_checksum();
			ping.send(&addr, pkt);
			++i;
		}

		return 0;
	}
};
}; // namespace pingtrace

#endif