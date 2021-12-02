#ifndef TIMESTAMP_RECORDER_ECS_H
#define TIMESTAMP_RECORDER_ECS_H

#include "ecs/NetTopologyEcs.h"

namespace pingtrace {
struct EcsTimeStampStat {
	struct packet_num {
		uint32_t send_num;
		uint32_t reply_num;
		uint32_t lost_num;
	} packet_num;
	std::vector<EcsNetTopology::stage_info> stage;

	EcsTimeStampStat()
	{
		int size = EcsNetTopology::delays().size();
		packet_num.send_num = 0;
		packet_num.reply_num = 0;
		packet_num.lost_num = 0;
		stage.resize(size);
		for (int i = 0; i < size; ++i) {
			stage[i].delay_id = i;
		}
	}
};

struct EcsTimeStampResults {
	bool timeout;
	struct meta {
		in_addr_t dstip;
		uint32_t seq;
		uint64_t ts_start;
		uint64_t ts_end;
		std::string time_unit;
	} meta;

	std::vector<EcsNetTopology::point_info> points;
	std::vector<EcsNetTopology::delay_info> delay;

	struct base_info {
		const char *name;
		int64_t base;
	};
	std::vector<base_info> base;

	struct other {
		std::vector<struct pingtrace_timestamp> unkonwn_points;
	} other;
	EcsTimeStampStat stat;

	EcsTimeStampResults() : stat()
	{
		auto &ps = EcsNetTopology::points();
		auto &ds = EcsNetTopology::delays();

		timeout = false;
		meta.dstip = 0;
		meta.seq = 0;
		meta.ts_start = 0;
		meta.ts_end = 0;
		meta.time_unit = "usec";

		delay.resize(ds.size());
		for (int i = 0; i < ds.size(); ++i) {
			delay[i].delay_id = i;
		}
	}

	uint32_t total_delay_ns() const
	{
		return meta.ts_end - meta.ts_start;
	}

	bool is_timeout()
	{
		return timeout;
	}
};
class EcsTimeStampRecorder {
	std::vector<EcsNetTopology::stage_info> stages;
	uint32_t send_count;
	uint32_t reply_count;
	std::unordered_map<int, DelayRecorder> delay_historys;

public:
	EcsTimeStampRecorder()
	{
		int idx = 0;
		stages.resize(EcsNetTopology::delays().size());
		for (auto &stage : stages) {
			stage.delay_id = idx;
			idx++;
			stage.max_delay = INT32_MIN;
			stage.min_delay = INT32_MAX;
			stage.sum_delay = 0;
			stage.mask = false;
		}
		send_count = reply_count = 0;
	}

private:
	void process_normal_delays(EcsTimeStampResults &tsr)
	{
		for (auto &d : EcsNetTopology::normal_delays()) {
			if (tsr.points[d.start_point_id].mask && tsr.points[d.end_point_id].mask) {
				int32_t delay;

				delay = tsr.points[d.end_point_id].ts - tsr.points[d.start_point_id].ts;

				tsr.delay[d.delay_id].ts = delay;
				tsr.delay[d.delay_id].mask = true;
				tsr.delay[d.delay_id].delay_id = d.delay_id;
				tsr.delay[d.delay_id].ts = delay;
			}
		}
	}

	void process_relative_delays(EcsTimeStampResults &tsr)
	{
		for (auto &d : EcsNetTopology::relative_delays()) {
			uint32_t start, end, delay;
			int64_t base_delay;
			bool start_mask = false, end_mask = false;

			for (auto id : d.start_candidate) {
				if (tsr.points[id].mask) {
					start_mask = true;
					start = tsr.points[id].ts;
				}
			}
			for (auto id : d.end_candidate) {
				if (tsr.points[id].mask) {
					end_mask = true;
					end = tsr.points[id].ts;
				}
			}

			if (start_mask && end_mask) {
				delay = end - start;
				tsr.delay[d.delay_id].mask = true;
				delay = delay_historys[d.delay_id].record(start, end);
				base_delay = delay_historys[d.delay_id].query();

				tsr.delay[d.delay_id].ts = delay;
				tsr.base.push_back({d.base_name, base_delay});
			} else {
				base_delay = delay_historys[d.delay_id].query();
				tsr.base.push_back({d.base_name, base_delay});
			}
		}
	}

	void process_view_delays(EcsTimeStampResults &tsr)
	{
		for (auto &d : EcsNetTopology::view_delays()) {
			tsr.delay[d.delay_id_view].mask = tsr.delay[d.delay_id_origin].mask;
			tsr.delay[d.delay_id_view].ts = tsr.delay[d.delay_id_origin].ts;
		}
	}

public:
	EcsTimeStampResults process(const TsList &tsl, in_addr_t dstip, uint32_t seq)
	{
		EcsTimeStampResults tsr;

		tsr.meta.dstip = dstip;
		tsr.meta.seq = seq;
		tsr.meta.ts_start = tsl.start_ts;
		tsr.timeout = tsl.timeout;
		tsr.meta.ts_end = tsl.end_ts;

		send_count++;
		if (tsl.timeout)
			return tsr;

		tsr.points = EcsNetTopology::process_ordered_timestamps(tsl);

		process_normal_delays(tsr);
		process_relative_delays(tsr);
		process_view_delays(tsr);

		// statistics
		reply_count++;
		for (auto &stage : stages) {
			if (!tsr.delay[stage.delay_id].mask)
				continue;
			stage.max_delay = std::max(stage.max_delay, tsr.delay[stage.delay_id].ts);
			stage.min_delay = std::min(stage.min_delay, tsr.delay[stage.delay_id].ts);
			stage.sum_delay += tsr.delay[stage.delay_id].ts;
			stage.mask = true;
		}
		tsr.stat = get_statistics_data();

		return tsr;
	}

	EcsTimeStampStat get_statistics_data()
	{
		EcsTimeStampStat stat;
		stat.packet_num.send_num = send_count;
		stat.packet_num.reply_num = reply_count;
		stat.packet_num.lost_num = send_count - reply_count;
		stat.stage = stages;
		for (auto &stage : stat.stage) {
			if (reply_count)
				stage.avg_delay = stage.sum_delay / reply_count;
			else
				stage.avg_delay = 0;
		}
		return stat;
	}
};
}; // namespace pingtrace

#endif