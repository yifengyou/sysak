#ifndef EBPF_RESULT_H
#define EBPF_RESULT_H

#include "bpf/libbpf.h"
#include "map_define.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>
#include <vector>

class eBPFResult {
private:
	struct pingtrace_map_value value;

public:
	eBPFResult()
	{
		memset(&value, 0, sizeof(value));
		value.softirq_ts = -1;
	}

	// this func must read map value eagerly, because the value maybe deleted.
	static eBPFResult from(int map_fd, pingtrace_map_key *key)
	{
		eBPFResult result;

		bpf_map_lookup_elem(map_fd, key, &result.value);
		return result;
	}

	std::vector<pingtrace_map_entry> points()
	{
		int ret;
		std::vector<pingtrace_map_entry> vts;

		for (int i = 0; i < PINGTRACE_MAP_ENTRY_NUM; ++i) {
			struct pingtrace_map_entry *entry;
			entry = &value.entries[i];

			if (entry->function_id && entry->ns)
				vts.push_back(*entry);
			else
				break;
		}
		return vts;
	}

	uint64_t softirq_ts()
	{
		return value.softirq_ts;
	}
};

#endif