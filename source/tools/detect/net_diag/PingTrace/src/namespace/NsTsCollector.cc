#include "namespace/NsTsCollector.h"
#include "netmodel/TsList.h"
#include "netmodel/TsCollector.h"

namespace pingtrace{

void NsTsCollector::collect(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact, uint16_t user_id, uint32_t ns_id)
{
	pingtrace_map_key key;
	key.seq = pkt_kern.seq();
	key.id = pkt_kern.id();

	// push start
	tsl.push_back(TsCollector::convert_from_ts_with_userid(P_L_TX_USER, start_ts, user_id, ns_id));

	// push request kern
	auto req_kern_res = bpf.query_tx_points(&key).points();
	tsl.merge(TsCollector::convert(req_kern_res));

	// relpy remote
	TsCollector::collect_remote_ts(pkt_compact, tsl);

	//reply kern
	auto reply_kern_res = bpf.query_rx_points(&key).points();
	tsl.merge(TsCollector::convert(reply_kern_res));

	tsl.push_back(TsCollector::convert_from_ts_with_userid(P_L_RX_USER, end_ts, user_id, ns_id));

	tsl.set_start(start_ts);
	tsl.set_end(end_ts);
}

}