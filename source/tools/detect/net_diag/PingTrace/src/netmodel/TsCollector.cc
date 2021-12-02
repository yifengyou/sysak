#include "netmodel/TsCollector.h"
#include "netmodel/TsList.h"

namespace pingtrace {

void TsCollector::collect_remote_ts(PingTracePacket &pkt, TsList &tsl)
{
	if (!pkt.valid()) return;
	for (int i = config::packet_reserve_entry_num; i < pkt.entry_num(); ++i) {
		tsl.push_back(pkt.get_timestamp(i));
	}
}

std::vector<pingtrace_timestamp> TsCollector::convert(std::vector<pingtrace_map_entry> &src)
{
	return convert_with_userid(src, 0);
}

std::vector<pingtrace_timestamp> TsCollector::convert_with_userid(std::vector<pingtrace_map_entry> &src, uint16_t user_id)
{
	std::vector<pingtrace_timestamp> res;
	for (auto &entry : src) {
		pingtrace_timestamp ts;
		ts.ns_id = entry.net_inum;
		ts.function_id = entry.function_id;
		ts.ts = util::ns_truncate(entry.ns);
		ts.ifindex = entry.ifindex;
		ts.user_id = user_id;
		res.push_back(ts);
	}
	return res;
}

pingtrace_timestamp TsCollector::convert_from_ts_with_userid(uint16_t function_id, uint64_t ts, uint16_t user_id, uint32_t ns_id)
{
	pingtrace_timestamp res;

	memset(&res, 0, sizeof(pingtrace_timestamp));
	res.function_id = function_id;
	res.ts = util::ns_truncate(ts);
	res.user_id = user_id;
	res.ns_id = ns_id;
	return res;
}

pingtrace_timestamp TsCollector::convert_from_ts(uint16_t function_id, uint64_t ts)
{
	return convert_from_ts_with_userid(function_id, ts, 0, 0);
}

} // namespace pingtrace