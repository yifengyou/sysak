#ifndef NET_MODEL_ECS_H
#define NET_MODEL_ECS_H

#include "EcsTsCollector.h"
#include "ecs/DisplayerEcs.hpp"
#include "netmodel/NetModel.h"

namespace pingtrace {
class EcsNetModel : public NetModel {
	EcsTsCollector collector;
	std::shared_ptr<EcsDisplayer> display;
	EcsTimeStampRecorder recorder;

public:
	EcsNetModel(options *opt, sockaddr_in &addr, uint32_t id) : NetModel(addr, 0, MODE_AUTO), collector(opt, id), display(EcsDisplayer::init_displayer(opt)), recorder() {}

public:
	virtual void prog_start() {}
	virtual void send_begin()
	{
		collector.start();
	}
	virtual void send_end()
	{
		collector.reset_sched_ts();
		next_sequence();
	}
	virtual void receive_begin() {}
	virtual void receive_end(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact)
	{
		if (!pkt_compact.valid())
			status.notify_pkt_miss();
		collector.collect(pkt_kern, pkt_compact);
	}
	virtual void receive_timeout()
	{
		collector.set_timeout();
	}
	virtual void receive_kern_packet()
	{
		collector.end();
	}
	virtual void receive_cur_compact_packet()
	{
		status.notify_compact_pkt_get();
	}
	virtual void receive_last_compact_packet()
	{
		status.notify_compact_pkt_get();
	}
	virtual void receive_bad_packet() {}
	virtual void prog_end()
	{
		display->end_print(recorder.get_statistics_data());
	}
	virtual void show(options *opt)
	{
		display->print(recorder.process(collector.get_results(), addr.sin_addr.s_addr, seq),
					   util::us_to_ns(opt->max_delay));
	}
};

}; // namespace pingtrace
#endif