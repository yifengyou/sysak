#ifndef TIMESTAMP_RECORDER_NAMESPACE_H
#define TIMESTAMP_RECORDER_NAMESPACE_H

#include "netmodel/TsList.h"
#include <unordered_map>

namespace pingtrace
{
struct NamespaceTimeStampResult {
	std::vector<int32_t> delays;
};

class NamespaceTimeStampRecorder
{
  public:
	struct PointId {
		union {
			struct {
			uint32_t ifindex;
			uint32_t nsid;
			uint16_t userid;
			uint16_t function_id;
			};
			char buf[0];
		};

		PointId()
		{
			memset(buf, 0, sizeof(PointId));
		}
		bool operator==(const PointId &rhs) const
		{
			return ifindex == rhs.ifindex &&
				nsid == rhs.nsid &&
				userid == rhs.userid &&
				function_id == rhs.function_id;
		}
	};

	struct DelayKey {
		PointId start_id;
		PointId end_id;

		bool operator==(const DelayKey &rhs) const
		{
			return start_id == rhs.start_id &&
				end_id == rhs.end_id;
		}
	};

	struct DelayKeyCompare {
		std::size_t hash_impl(const PointId &id, unsigned hash) const
		{
			unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
			const char *buf = &id.buf[0];
			int i = 0;

			while (i < sizeof(id)) {
			hash = hash * seed + buf[i];
			i++;
			}

			return (hash & 0x7FFFFFFF);
		}
		std::size_t operator()(const DelayKey &key) const
		{
			unsigned hash = 0;
			hash = hash_impl(key.start_id, hash);
			hash = hash_impl(key.end_id, hash);
			return hash;
		}
	};

	struct StatValue {
		int32_t min_delay;
		int32_t max_delay;
		int64_t sum_delay;
		int num;

		StatValue() : min_delay(INT32_MAX), max_delay(INT32_MIN), sum_delay(0), num(0) {}
	};

  private:
	std::unordered_map<DelayKey, DelayRecorder, DelayKeyCompare> delay_recorder;
	std::unordered_map<DelayKey, StatValue, DelayKeyCompare> stat_recorder;
	uint64_t send_num;
	uint64_t reply_num;

  private:
	int32_t record_relative_delay(const DelayKey &key, uint32_t start, uint32_t end)
	{
		auto &v = delay_recorder[key];
		int32_t delay;

		delay = v.record(start, end);
		record_normal_delay(key, delay);
		return delay;
	}

	void record_normal_delay(const DelayKey &key, int32_t delay)
	{
		auto &v = stat_recorder[key];

		v.max_delay = std::max(v.max_delay, delay);
		v.min_delay = std::min(v.min_delay, delay);
		v.sum_delay += delay;
		v.num++;
	}

	DelayKey key_build(const pingtrace_timestamp &last, const pingtrace_timestamp &cur)
	{
		DelayKey key;

		key.start_id.function_id = last.function_id;
		key.start_id.ifindex = last.ifindex;
		key.start_id.nsid = last.ns_id;
		key.start_id.userid = last.user_id;
		key.end_id.function_id = cur.function_id;
		key.end_id.ifindex = cur.ifindex;
		key.end_id.nsid = cur.ns_id;
		key.end_id.userid = cur.user_id;
		return key;
	}

  public:
	NamespaceTimeStampRecorder() : send_num(0), reply_num(0) {}
	NamespaceTimeStampResult record(const TsList &tsl)
	{
		NamespaceTimeStampResult tsr;

		send_num++;
		if (tsl.timeout)
			return tsr;
		reply_num++;

		for (int i = 1; i < tsl.list.size(); ++i) {
			auto &last = tsl.list[i - 1];
			auto &cur = tsl.list[i];
			int32_t val = cur.ts - last.ts;
			DelayKey key = key_build(last, cur);

			if (last.user_id == cur.user_id)
			record_normal_delay(key, val);
			else
			val = record_relative_delay(key, last.ts, cur.ts);
			tsr.delays.push_back(val);
		}
		return tsr;
	}
	const std::unordered_map<DelayKey, StatValue, DelayKeyCompare> &get()
	{
		return stat_recorder;
	}
};
}; // namespace pingtrace

#endif