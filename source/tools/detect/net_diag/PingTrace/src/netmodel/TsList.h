#ifndef TS_LIST_H
#define TS_LIST_H

#include "common/common.h"
#include <vector>

namespace pingtrace {

struct TsList {
	uint64_t start_ts, end_ts;
	std::vector<pingtrace_timestamp> list;
	bool timeout;

	TsList() : list(), timeout(false) {}

	void clear()
	{
		start_ts = end_ts = 0;
		timeout = false;
		list.clear();
	}

	void set_timeout() { timeout = true; }
	void set_start(uint64_t ts) { start_ts = ts; }
	void set_end(uint64_t ts) { end_ts = ts; }
	void push_back(const pingtrace_timestamp &ts) { list.push_back(ts); }

	void merge(const std::vector<pingtrace_timestamp> &rhs)
	{
		for (auto &ts : rhs)
			list.push_back(ts);
	}

	uint32_t total_delay_ns() const { return end_ts - start_ts; }
};
}; // namespace pingtrace
#endif