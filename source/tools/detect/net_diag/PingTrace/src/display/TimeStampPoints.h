#ifndef TIMESTAMP_POINTS_H
#define TIMESTAMP_POINTS_H

#include "common/common.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <vector>

namespace pingtrace
{
struct TimeStampPoints {
	std::vector<struct pingtrace_timestamp> points;
	in_addr_t dstip;
	uint32_t seq;
	uint64_t start_ts, end_ts;
	bool timeout;
	uint16_t user_id;
	uint32_t ns_id;

	TimeStampPoints() :
		dstip(0), seq(0), start_ts(0),
		end_ts(0), timeout(false), user_id(0), ns_id(0)
	{}

	void push_back(const struct pingtrace_timestamp &ts)
	{
		points.push_back(ts);
	}

	void push_back(uint32_t ns_id, uint16_t function_id, uint32_t ts, uint32_t ifindex, uint16_t userid)
	{
		struct pingtrace_timestamp entry;
		entry.ns_id = ns_id;
		entry.ifindex = ifindex;
		entry.function_id = function_id;
		entry.ts = ts;
		entry.user_id = userid;
		points.push_back(entry);
	}

	void set_seq(uint32_t seq)
	{
		this->seq = seq;
	}

	void set_meta(uint32_t seq, in_addr_t dstip)
	{
		this->seq = seq;
		this->dstip = dstip;
	}

	void set_start_ns(uint64_t start)
	{
		this->start_ts = start;
	}

	void set_end_ns(uint64_t end)
	{
		this->end_ts = end;
	}

	void set_timeout()
	{
		timeout = true;
	}

	void clear()
	{
		points.clear();
		timeout = false;
	}

	void set_ids(uint32_t nsid, uint16_t userid)
	{
		this->ns_id = nsid;
		this->user_id = userid;
	}

	uint32_t total_delay_ns() const
	{
		return end_ts - start_ts;
	}
};
}; // namespace pingtrace

#endif