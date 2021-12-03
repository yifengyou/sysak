#ifndef NS_TS_COLLECTOR_H
#define NS_TS_COLLECTOR_H

#include "bpf/NsSendBPF.hpp"
#include "netmodel/TsList.h"

namespace pingtrace {

class NsTsCollector {

public:
	NsSenderBPF bpf;
	uint64_t start_ts, end_ts;
	TsList tsl;

public:
	NsTsCollector(options *opt) : bpf(opt), start_ts(0), end_ts(0), tsl() {}
	void start()
	{
		tsl.clear();
		start_ts = util::get_time_ns();
	}

	void end()
	{
		end_ts = util::get_time_ns();
	}

	void set_timeout()
	{
		tsl.set_timeout();
	}

	TsList &get_results()
	{
		return tsl;
	}

	void collect(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact, uint16_t user_id, uint32_t ns_id);
};

}; // namespace pingtrace

#endif