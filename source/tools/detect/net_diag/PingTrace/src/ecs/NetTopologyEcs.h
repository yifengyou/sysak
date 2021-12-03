#ifndef NET_TOPOLOGY_ECS_H
#define NET_TOPOLOGY_ECS_H

#include "netmodel/TsList.h"

namespace pingtrace {
struct EcsNetTopology : public NetTopology {
	struct delay_name {
		const char *name;
		int delay_id;
	};

	struct relative_delay_info {
		const char *base_name;
		int delay_id;
		std::vector<uint32_t> start_candidate;
		std::vector<uint32_t> end_candidate;
	};

	struct normal_delay_info {
		int delay_id;
		int start_point_id;
		int end_point_id;
	};

	struct abs_correction_delay_info {
		int delay_id;
		int start_point_id;
		int end_point_id;
	};

	struct view_delay_info {
		int delay_id_view;
		int delay_id_origin;
	};

	struct point_info {
		uint64_t node_id;
		uint32_t ts;
		int point_id;
		bool mask;
	};

	struct delay_info {
		int32_t ts;
		int delay_id;
		bool mask;
	};

	struct stage_info {
		int32_t delay_id;
		int32_t min_delay;
		int32_t max_delay;
		union {
			int64_t sum_delay;
			int32_t avg_delay;
		};
		bool mask;
	};

	enum pingtrace_delay {
		D_TOTAL,
		D_L_TX_KERN,
		D_L_TX_QDISC,
		D_L_TX_OUTLINK,
		D_R_TX_KERN,
		D_R_RX_KERN,

		D_L_RX_INLINK,
		D_L_RX_KERN,

		D_L_RX_TASK_WAKING,
		D_L_RX_TASK_QUEUE,

		D_L_RX_SOFTIRQ,

		D_L_TX_MERGED_KERN,
		D_L_TX_MERGED_OUTLINK,
		D_R_TX_MERGED_KERN,
		D_R_RX_MERGED_KERN,
		D_L_RX_MERGED_INLINK,
		D_L_RX_MERGED_KERN,

		PD_NUM
	};

private:
	static void delays_init_and_validate(std::vector<delay_name> &delays) {
		static bool inited = false;

		if (inited)
			return;
		sort(delays.begin(), delays.end(),
			[](const delay_name &a, const delay_name &b)
			{ return a.delay_id < b.delay_id; });

		inited = true;
	}

public:
	static const std::vector<delay_name> &delays() {
		static std::vector<delay_name> delay_names = {
			{"total", D_TOTAL},
			{"l_tx_kern", D_L_TX_KERN},
			{"l_tx_qdisc", D_L_TX_QDISC},
			{"l_tx_outlink", D_L_TX_OUTLINK},
			{"r_tx_kern", D_R_TX_KERN},
			{"r_rx_kern", D_R_RX_KERN},
			{"l_rx_inlink", D_L_RX_INLINK},
			{"l_rx_kern", D_L_RX_KERN},
			{"l_rx_task_waking", D_L_RX_TASK_WAKING},
			{"l_rx_task_queue", D_L_RX_TASK_QUEUE},
			{"l_rx_softirq", D_L_RX_SOFTIRQ},

			{"l_tx_merged_kern", D_L_TX_MERGED_KERN},
			{"l_tx_merged_outlink", D_L_TX_MERGED_OUTLINK},
			{"r_tx_merged_kern", D_R_TX_MERGED_KERN},
			{"r_rx_merged_kern", D_R_RX_MERGED_KERN},
			{"l_rx_merged_inlink", D_L_RX_MERGED_INLINK},
			{"l_rx_merged_kern", D_L_RX_MERGED_KERN},
		};
		delays_init_and_validate(delay_names);
		return delay_names;
	}

	static bool is_image_display_stat_white_list(int delay_id)
	{
		static bool first_time = true;
		static std::vector<char> white_list;

		if (first_time) {
			first_time = false;
			static std::vector<int> white_list_ids = {
				D_TOTAL, D_L_TX_KERN, D_L_TX_QDISC, D_L_TX_OUTLINK,
				D_R_TX_KERN, D_R_RX_KERN, D_L_RX_INLINK, D_L_RX_KERN,
				D_L_RX_TASK_WAKING, D_L_RX_TASK_QUEUE, D_L_RX_SOFTIRQ,
			};

			white_list.clear();
			white_list.resize(PD_NUM, 0);
			for (auto &id : white_list_ids)
				white_list[id] = 1;
		}
		return white_list[delay_id];
	}

	static const char *get_delay_name(int delay_id)
	{
		auto &d = delays();
		return d[delay_id].name;
	}

	static const std::vector<relative_delay_info> &relative_delays()
	{
		// The outlink/inlink latency is important to analyse latency,
		// but maybe we would miss some point during transmission
		// so that outlink/inlink latency is uncalculatable.
		// To calcalute such latency when miss some important points,
		// these latency would be calculated by some candidate points.
		// Now there is only one candidate point, but it could be expanded.
		const static std::vector<relative_delay_info> relative_delays_arr = {
			{"outlink_base", D_L_TX_OUTLINK,
				{P_L_TX_DEVOUT},
				{P_R_RX_IPRCV}
			},
			{"inlink_base", D_L_RX_INLINK,
				{P_R_TX_DEVOUT},
				{P_L_RX_IPRCV}
			}
		};
		return relative_delays_arr;
	}

	static const std::vector<normal_delay_info> &normal_delays()
	{
		static const std::vector<normal_delay_info> normal_delays_arr = {
			{D_TOTAL, P_L_TX_USER, P_L_RX_USER},
			{D_L_TX_KERN, P_L_TX_USER, P_L_TX_DEVQUEUE},
			{D_L_TX_QDISC, P_L_TX_DEVQUEUE, P_L_TX_DEVOUT},
			{D_R_RX_KERN, P_R_RX_IPRCV, P_R_RX_ICMPRCV},
			{D_R_TX_KERN, P_R_RX_ICMPRCV, P_R_TX_DEVOUT},
			{D_L_RX_KERN, P_L_RX_IPRCV, P_L_RX_SKDATAREADY},
			{D_L_RX_TASK_WAKING, P_L_RX_SKDATAREADY, P_L_RX_WAKEUP},
			{D_L_RX_TASK_QUEUE, P_L_RX_WAKEUP, P_L_RX_USER},
			{D_L_TX_MERGED_KERN, P_L_TX_USER, P_L_TX_DEVOUT},
			{D_L_RX_MERGED_KERN, P_L_RX_IPRCV, P_L_RX_USER},
			{D_L_RX_SOFTIRQ, P_L_RX_SOFTIRQ, P_L_RX_IPRCV},
		};
		return normal_delays_arr;
	}

	static const std::vector<view_delay_info> &view_delays() {
		static const std::vector<view_delay_info> view_delays_arr = {
			{D_L_TX_MERGED_OUTLINK, D_L_TX_OUTLINK},
			{D_R_TX_MERGED_KERN, D_R_TX_KERN},
			{D_R_RX_MERGED_KERN, D_R_RX_KERN},
			{D_L_RX_MERGED_INLINK, D_L_RX_INLINK},
		};
		return view_delays_arr;
	}

	static std::vector<point_info> process_ordered_timestamps(const TsList &tsl) {
		std::vector<point_info> vp;
		auto &ps = points();
		int i = 0;

		vp.resize(P_L_ECS_POINT_NUM);
		for (auto &p : vp)
			p.point_id = i++;

		for (auto &ts : tsl.list) {
			if (ts.function_id >= 0 && ts.function_id < PP_NUM) {
				int32_t point_id = ts.function_id;
				vp[point_id].mask = true;
				vp[point_id].node_id = ts.machine_id;
				vp[point_id].point_id = point_id;
				vp[point_id].ts = ts.ts;
			}
		}

		// special dealing with L_RX_WAKEUP, this point may be a slower value if process didn't sleep during receiving packet.
		if (vp[P_L_RX_WAKEUP].mask && vp[P_L_RX_SKDATAREADY].mask) {
			if ((int32_t)(vp[P_L_RX_WAKEUP].ts) < (int32_t)(vp[P_L_RX_SKDATAREADY].ts))
				vp[P_L_RX_WAKEUP].mask = false;
		}

		return vp;
	}
};
}; // namespace pingtrace

#endif