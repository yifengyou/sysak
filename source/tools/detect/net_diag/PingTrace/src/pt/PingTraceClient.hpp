#ifndef PINGTRACE_CLIENT_H
#define PINGTRACE_CLIENT_H

#include "bpf/eBPFProg.h"
#include "display/TimeStampPoints.h"
#include "netmodel/NetModel.h"
#include "pt/Ping.hpp"
#include <memory>

namespace pingtrace {
class PingTraceClient : public PingTrace {
public:
	PingTraceClient() {}

private:
	void send(Ping &ping, std::shared_ptr<NetModel> &nm, int max_entry_num)
	{
		PingTracePacket pkt;
		pkt.init(max_entry_num);
		pkt.pack(nm->cur_sequence(), id, config::packet_reserve_entry_num);
		ping.send(&nm->remote(), pkt);
	}

	bool is_compact_pkt(PingTracePacket &pkt, uint16_t recent_seq)
	{
		int64_t seq = recent_seq;
		int64_t pkt_seq = pkt.seq();

		return (pkt.flags() & PINGTRACE_F_DONTADD) &&
				pkt_seq >= recent_seq - config::compact_packet_seq_detect_range &&
				pkt_seq <= recent_seq + config::compact_packet_seq_detect_range;
	}

	bool recv_pingpong(Ping &ping, std::shared_ptr<NetModel> &nm, bool &ret_timeout)
	{
		PingTracePacket pkt;
		uint64_t start, end;
		uint32_t recent_seq = nm->cur_sequence() - 1;
		bool ret, timeout = false;

		pkt.init(config::max_entry_num);
		start = util::get_time_ns();

		nm->receive_begin();
		while (1) {
			ret = recv_and_parse(ping, pkt, nm->remote(), timeout);
			end = util::get_time_ns();
			if (!ret || timeout) {
				if (!ret) {
					nm->receive_bad_packet();
					if (util::ns_to_us(end - start) < config::timeout_threshold_us)
						continue;
				} else {
					nm->receive_timeout();
					ret_timeout = true;
				}
				return false;
			}

			if (pkt.seq() != recent_seq) {
				if (is_compact_pkt(pkt, recent_seq))
					nm->receive_last_compact_packet();
				if (util::ns_to_us(end - start) < config::timeout_threshold_us)
					continue;

				nm->receive_timeout();
				ret_timeout = true;
				return false;
			}
			nm->receive_kern_packet();
			break;
		}
		nm->receive_end(pkt, pkt);

		return true;
	}

	bool recv_compact(Ping &ping, std::shared_ptr<NetModel> &nm, bool &ret_timeout)
	{
		PingTracePacket pkt_kern, pkt_compact, tmp;
		uint64_t ts_kern_end, ts_compact_end;
		uint64_t ts_kern_wakeup = 0, ts_compact_wakeup = 0;
		uint64_t start, end;
		bool timeout = false;

		tmp.init(config::max_entry_num);
		start = util::get_time_ns();
		nm->receive_begin();
		while (1) {
			bool ret;
			uint16_t flags;

			ret = recv_and_parse(ping, tmp, nm->remote(), timeout);
			if (timeout)
				break;
			end = util::get_time_ns();
			if (!ret) {
				nm->receive_bad_packet();
				if (util::ns_to_us(end - start) < config::timeout_threshold_us)
					continue;
				break;
			}
			if (tmp.seq() != nm->cur_sequence() - 1) {
				if (util::ns_to_us(end - start) < config::timeout_threshold_us)
					continue;
				break;
			}

			flags = tmp.flags();
			if ((flags & PINGTRACE_F_DONTADD) && !pkt_compact.valid()) {
				pkt_compact = std::move(tmp);
				nm->receive_cur_compact_packet();
				tmp.init(config::max_entry_num);
			}
			else if (!(flags & PINGTRACE_F_DONTADD) && !pkt_kern.valid()) {
				pkt_kern = std::move(tmp);
				nm->receive_kern_packet();
				tmp.init(config::max_entry_num);
			}

			if (pkt_kern.valid() && pkt_compact.valid())
				break;
		}

		if (pkt_kern.valid())
			nm->receive_end(pkt_kern, pkt_compact);
		else {
			nm->receive_timeout();
			ret_timeout = true;
		}
		return true;
	}

	bool recv_auto(Ping &ping, std::shared_ptr<NetModel> &nm, bool &timeout)
	{
		if (nm->cur_mode() == MODE_PINGPONG)
			return recv_pingpong(ping, nm, timeout);
		else
			return recv_compact(ping, nm, timeout);
	}

	bool recv(Ping &ping, std::shared_ptr<NetModel> &nm, bool &timeout)
	{
		switch (nm->run_mode()) {
		case MODE_PINGPONG:
			return recv_pingpong(ping, nm, timeout);
		break;
		case MODE_COMPACT:
			return recv_compact(ping, nm, timeout);
		break;
		case MODE_AUTO:
			return recv_auto(ping, nm, timeout);
		break;
		default:
		break;
		}
		return false;
	}

public:
	void run(struct options *opt)
	{
		std::shared_ptr<NetModel> nm = NetModel::init(opt, id);
		Ping ping(1 << ICMP_ECHOREPLY, false,
				  std::max((uint64_t)(opt->interval_us),
				  config::timeout_threshold_us));
		uint64_t count = 0;

		ping.set_bpf_filter(id);
		set_signal_callback(opt->runtime);

		nm->prog_start();
		for (count = 0; !stop && count < opt->max_count; ++count) {
			bool timeout = false, ret;

			nm->send_begin();
			send(ping, nm, opt->entry_num);
			nm->send_end();
			ret = recv(ping, nm, timeout);

			if (!ret) {
				if (timeout)
					nm->show(opt);
				goto sleep_and_continue;
			}
			nm->show(opt);
sleep_and_continue:
			if (!timeout && !opt->adaptive)
				usleep(opt->interval_us);
			timeout = false;
		}
		nm->prog_end();
	}
};

}; // namespace pingtrace

#endif