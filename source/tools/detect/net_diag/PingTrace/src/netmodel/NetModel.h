#ifndef NET_MODEL_INTERNAL_H
#define NET_MODEL_INTERNAL_H

#include "bpf/eBPFProg.h"
#include "common/options.hpp"
#include "display/Displayer.h"
#include "display/TimeStampPoints.h"
#include "display/TimeStampRecorder.h"
#include "pt/Packet.hpp"
#include "pt/PingReceiveStatus.hpp"
#include <arpa/inet.h>
#include <memory>
#include <stdint.h>

namespace pingtrace {

class NetModel {
protected:
	sockaddr_in addr;
	uint32_t seq;
	PingReceiveStatus status;

public:
	NetModel(sockaddr_in &addr, uint32_t init_seq, enum run_mode mode) : addr(addr), seq(init_seq), status(mode) {}
	uint32_t next_sequence()
	{
		seq++;
		return seq - 1;
	}
	const sockaddr_in &remote() { return addr; }
	uint32_t cur_sequence() { return seq; }
	enum run_mode cur_mode() { return status.current_mode(); }
	enum run_mode run_mode() { return status.run_mode(); }

public:
	virtual void prog_start() {}
	virtual void send_begin() {}
	virtual void send_end() {}
	virtual void receive_begin() {}
	virtual void receive_end(PingTracePacket &pkt_kern, PingTracePacket &pkt_compact) {}
	virtual void receive_timeout() {}
	virtual void receive_kern_packet() {}
	virtual void receive_cur_compact_packet() {}
	virtual void receive_last_compact_packet() {}
	virtual void receive_bad_packet() {}
	virtual void prog_end() {}
	virtual void show(options *opt) {}

public:
	static std::shared_ptr<NetModel> init(options *opt, uint32_t id);
};
}; // namespace pingtrace

#endif