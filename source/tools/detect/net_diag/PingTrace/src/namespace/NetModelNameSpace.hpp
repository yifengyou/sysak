#ifndef NET_MODEL_NAMESPACE_H
#define NET_MODEL_NAMESPACE_H

#include "namespace/DisplayerNamespace.hpp"
#include "netmodel/NetModel.h"
#include "namespace/NsTsCollector.h"
#include <memory>

namespace pingtrace
{
class NamespaceNetModel : public NetModel
{
	NsTsCollector collector;
	std::shared_ptr<NamespaceJsonDisplayer> display;
	NamespaceTimeStampRecorder recorder;
	bool is_remote_same_node;
	uint16_t user_id;
	uint32_t ns_id;

public:
	NamespaceNetModel(options *opt, sockaddr_in &addr)
	: NetModel(addr, 0, MODE_AUTO), collector(opt),
	  display(NamespaceJsonDisplayer::init(opt)),
	  recorder(), is_remote_same_node(opt->is_ns_local),
	  user_id(opt->user_id), ns_id(util::get_ns_id())
	{
	}
	virtual void prog_start() {}
	virtual void send_begin()
	{
		collector.start();
	}
	virtual void send_end()
	{
		next_sequence();
	}
	virtual void receive_begin() {}
	virtual void receive_end(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact)
	{
		if (!pkt_compact.valid())
			status.notify_pkt_miss();
		collector.collect(pkt_kern, pkt_compact, user_id, ns_id);
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
		display->end_print(recorder);
	}
	virtual void show(options *opt)
	{
		display->print(collector.get_results(), recorder,
					   util::us_to_ns(opt->max_delay), seq);
	}
};
}; // namespace pingtrace

#endif