#include "config.h"

namespace pingtrace
{
	const std::string config::version = "PingTrace v2.0";
	const uint64_t config::timeout_threshold_us = 1000000;
	const int config::test_pkt_num = 3;
	const uint64_t config::log_max_size = 256 * 1024 * 1024;
	const uint64_t config::log_max_backup = 3;
	const char *config::log_name = "./pingtrace.log";
	const int32_t config::compact_packet_seq_detect_range = 3;
	const int32_t config::compact_pkt_miss_threshold = 3;
	const int32_t config::max_entry_num = 90;
	const int32_t config::default_entry_num = 32;
	const int32_t config::packet_reserve_entry_num = 8;
}; // namespace pingtrace