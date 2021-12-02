#ifndef TIMESTAMP_RECORDER_INTERNAL_H
#define TIMESTAMP_RECORDER_INTERNAL_H

#include <queue>
#include <unordered_map>

namespace pingtrace
{
class DelayRecorder
{
	struct entry {
		uint32_t idx;
		int64_t delay;
	};
	uint32_t idx;
	std::deque<entry> q;
	uint32_t max_num;

private:
	void add(int64_t usec)
	{
		idx++;
		while (!q.empty() && q.back().delay >= usec)
			q.pop_back();
		q.push_back({idx, usec});
		while (!q.empty() && q.front().idx + max_num <= idx)
			q.pop_front();
	}

public:
	explicit DelayRecorder(int max_num = 10000) : max_num(max_num) {}
	int64_t query()
	{
		if (q.empty())
			return 0;
		return q.front().delay;
	}

	uint32_t record(uint32_t start, uint32_t end)
	{
		int32_t val32 = end - start;
		int64_t val = val32;
		int64_t base;

		add(val);
		base = query();
		return val - base;
	}
};
}; // namespace pingtrace

#endif