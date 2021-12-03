#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <unistd.h>

namespace pingtrace
{
struct util {
	static uint64_t get_time_us(void)
	{
		struct timespec ts;
		uint64_t usec;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		usec = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
		return usec;
	}
	static uint64_t get_time_ns(void)
	{
		struct timespec ts;
		uint64_t nsec;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		nsec = ts.tv_sec * 1000000000 + ts.tv_nsec;
		return nsec;
	}
	static uint32_t ns_truncate(uint64_t ns) { return (ns / 1000) & ((1UL << 32) - 1); }
	static uint32_t us_truncate(uint64_t us) { return us & ((1UL << 32) - 1); }
	static uint32_t get_time(void) { return us_truncate(get_time_us()); }
	static uint64_t second_to_us(uint64_t sec) { return sec * 1000000; }
	static uint64_t ns_to_us(uint64_t ns) { return ns / 1000; }
	static uint64_t us_to_ns(uint64_t us) { return us * 1000; }
	static uint32_t get_ns_id()
	{
		uint32_t id;
		char buf[256];

		if (readlink("/proc/self/ns/net", buf, sizeof(buf)) < 0)
			return 0;
		sscanf(buf, "net:[%d]", &id);
		return id;
	}
};
}; // namespace pingtrace

#endif