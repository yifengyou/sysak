#ifndef PING_RECEIVE_STATUS_H
#define PING_RECEIVE_STATUS_H

#include "common/common.h"
#include "common/config.h"

namespace pingtrace
{
struct PingReceiveStatus {
	enum run_mode mode;
	enum run_mode cur_mode;
	int compact_pkt_miss_count;

	PingReceiveStatus(enum run_mode mode) : mode(mode), cur_mode(mode), compact_pkt_miss_count(0)
	{
		if (mode == MODE_AUTO)
			cur_mode = MODE_COMPACT;
	}

	void notify_pkt_miss()
	{
		if (mode != MODE_AUTO)
			return;
		compact_pkt_miss_count++;
		if (compact_pkt_miss_count <= config::compact_pkt_miss_threshold)
			return;
		cur_mode = MODE_PINGPONG;
		compact_pkt_miss_count = 0;
	}

	void notify_compact_pkt_get()
	{
		if (mode != MODE_AUTO)
			return;
		cur_mode = MODE_COMPACT;
	}

	enum run_mode current_mode() { return cur_mode; }

	enum run_mode run_mode() { return mode; }
};
}; // namespace pingtrace

#endif