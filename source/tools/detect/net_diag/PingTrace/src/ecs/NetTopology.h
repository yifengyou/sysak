#ifndef NET_TOPOLOGY_INTERNAL_H
#define NET_TOPOLOGY_INTERNAL_H

#include "display/TimeStampPoints.h"
#include "common/common.h"
#include "common/options.hpp"
#include <cassert>
#include <memory>
#include <stdint.h>
#include <vector>

namespace pingtrace
{
struct NetTopology {
	struct point_name {
		const char *name;
		int point_id;
	};

private:
	static void points_sort_and_validate(std::vector<point_name> &point_names)
	{
		static bool inited = false;

		if (inited)
			return;
		std::sort(point_names.begin(), point_names.end(),
				  [](const point_name &a, const point_name &b)
				  	{ return a.point_id < b.point_id; });
		for (int i = 0; i < point_names.size(); ++i) {
			assert(point_names[i].point_id == i);
		}
		inited = true;
	}

public:
	static const std::vector<point_name> &points()
	{
		static std::vector<point_name> point_names = {
			{"l_tx_user", P_L_TX_USER},
			{"l_tx_devqueue", P_L_TX_DEVQUEUE},
			{"l_tx_devout", P_L_TX_DEVOUT},
			{"r_rx_icmprcv", P_R_RX_ICMPRCV},
			{"r_tx_devout", P_R_TX_DEVOUT},
			{"l_rx_iprcv", P_L_RX_IPRCV},
			{"l_rx_skdataready", P_L_RX_SKDATAREADY},
			{"l_rx_wakeup", P_L_RX_WAKEUP},
			{"l_rx_user", P_L_RX_USER},
			{"r_rx_devrcv", P_R_RX_IPRCV},
			{"l_rx_softirq", P_L_RX_SOFTIRQ},
			{"m_tx_devecho", P_M_TX_DEVECHO},
			{"m_rx_devecho", P_M_RX_DEVECHO},
			{"m_tx_devreply", P_M_TX_DEVREPLY},
			{"m_rx_devreply", P_M_RX_DEVREPLY},
		};
		points_sort_and_validate(point_names);
		return point_names;
	}
	static const char *get_points_name(int point_id)
	{
		auto &p = points();
		return p[point_id].name;
	}
};
}; // namespace pingtrace
#endif