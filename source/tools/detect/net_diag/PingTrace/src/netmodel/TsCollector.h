#ifndef TIMESTAMP_COLLECTOR_H
#define TIMESTAMP_COLLECTOR_H

#include "common/common.h"
#include "pt/Packet.hpp"
#include "netmodel/TsList.h"
#include <vector>

namespace pingtrace {
class TsCollector {
public:
    static void collect_remote_ts(PingTracePacket &pkt, TsList &tsl);
    static std::vector<pingtrace_timestamp> convert(std::vector<pingtrace_map_entry> &src);
    static std::vector<pingtrace_timestamp> convert_with_userid(std::vector<pingtrace_map_entry> &src, uint16_t user_id);
    static pingtrace_timestamp convert_from_ts(uint16_t function_id, uint64_t ts);
    static pingtrace_timestamp convert_from_ts_with_userid(uint16_t function_id, uint64_t ts, uint16_t user_id, uint32_t ns_id);
};
} // namespace pingtrace

#endif