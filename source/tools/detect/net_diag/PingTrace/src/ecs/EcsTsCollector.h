#ifndef TIMESTAMP_COLLECTOR_HPP
#define TIMESTAMP_COLLECTOR_HPP

#include "bpf/EcsSendBPF.hpp"
#include "bpf/EcsSendCompatBPF.hpp"
#include "common/util.hpp"
#include "netmodel/TsList.h"
#include "pt/Packet.hpp"
#include <memory>

namespace pingtrace {

class EcsTsCollector {

public:
	std::shared_ptr<EcsSenderBPFBase> bpf;
	uint64_t start_ts, end_ts, wakeup_ts;
	TsList tsl;

private:
	void init_bpf(options *opt, uint64_t id)
	{
	if (opt->compat)
		bpf = std::make_shared<EcsSenderCompatBPF>(opt, id);
	else
		bpf = std::make_shared<EcsSenderBPF>(opt);
	}

public:
	explicit EcsTsCollector(options *opt, uint32_t id) :
		bpf(), start_ts(0), end_ts(0),
		wakeup_ts(0), tsl()
	{
		init_bpf(opt, id);
	}
	void start()
	{
		tsl.clear();
		wakeup_ts = 0;
		bpf->clear_recorded_sched_time();
		start_ts = util::get_time_ns();
	}

	void reset_sched_ts()
	{
		bpf->clear_recorded_sched_time();
	}

	void end()
	{
		wakeup_ts = bpf->query_sched_time();
		end_ts = util::get_time_ns();
	}

	void set_timeout()
	{
		tsl.set_timeout();
	}

	const TsList &get_results()
	{
		return tsl;
	}

	void collect(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact);

private:
	void collect_reply_packet_kern_ts(pingtrace_map_key &key);
};

} // namespace pingtrace

#endif