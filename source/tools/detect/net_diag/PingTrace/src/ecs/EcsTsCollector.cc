#include "EcsTsCollector.h"
#include "common/common.h"
#include "netmodel/TsCollector.h"

namespace pingtrace {

void EcsTsCollector::collect_reply_packet_kern_ts(pingtrace_map_key &key)
{
	auto res = bpf->query_rx_points(&key);
	auto vts = res.points();
	uint64_t irq_ts = res.softirq_ts();

	if (vts.empty()) {
		return;
	}

	auto netstack_rcv_ts = vts[0];
	if (irq_ts != -1 && netstack_rcv_ts.ns > irq_ts) {
		tsl.push_back(TsCollector::convert_from_ts(P_L_RX_SOFTIRQ, irq_ts));
	}

	tsl.merge(TsCollector::convert(vts));
}

void EcsTsCollector::collect(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact)
{
	pingtrace_map_key key;
	key.seq = pkt_kern.seq();
	key.id = pkt_kern.id();

	// push start
	tsl.push_back(TsCollector::convert_from_ts(P_L_TX_USER, start_ts));

	// push request kern
	auto req_kern_res = bpf->query_tx_points(&key).points();
	tsl.merge(TsCollector::convert(req_kern_res));


	// relpy remote
	TsCollector::collect_remote_ts(pkt_compact, tsl);

	// softirq and reply kern
	collect_reply_packet_kern_ts(key);

	// wake up
	if (wakeup_ts) {
		tsl.push_back(TsCollector::convert_from_ts(P_L_RX_WAKEUP, wakeup_ts));
	}

	tsl.push_back(TsCollector::convert_from_ts(P_L_RX_USER, end_ts));
	// end

	tsl.set_start(start_ts);
	tsl.set_end(end_ts);
}

} // namespace pingtrace