#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <string>

namespace pingtrace
{

struct config {
	const static std::string version;
	const static int test_pkt_num;
	const static uint64_t timeout_threshold_us;
	const static uint64_t log_max_size;
	const static uint64_t log_max_backup;
	const static char *log_name;
	const static int32_t compact_packet_seq_detect_range;
	const static int32_t compact_pkt_miss_threshold;
	const static int32_t max_entry_num;
	const static int32_t default_entry_num;
	const static int32_t packet_reserve_entry_num;
};

}; // namespace pingtrace

#endif