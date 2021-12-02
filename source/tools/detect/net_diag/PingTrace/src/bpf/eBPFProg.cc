#include "bpf/eBPFProg.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {
static int set_unlimited() {
	struct rlimit l = {RLIM64_INFINITY, RLIM64_INFINITY};
	int ret;

	ret = setrlimit(RLIMIT_MEMLOCK, &l);
	if (ret < 0) {
		fprintf(stderr, "setrlimit failed, errno: %d\n", ret);
		fprintf(stderr, "do you have CAP_SYS_RESOURCE capability?\n");
	}
	return ret;
}

int BPFProg::preinit(bool debug) {
	if (!debug) {
		libbpf_set_print(NULL);
	} else {
		libbpf_set_print(libbpf_print_func);
	}
	return set_unlimited();
}

std::vector<pingtrace_map_entry> query_ts_array(pingtrace_map_key *key, int map_fd) {
	std::vector<pingtrace_map_entry> res;
	struct pingtrace_map_value value;

	bpf_map_lookup_elem(map_fd, key, &value);

	for (int i = 0; i < PINGTRACE_MAP_ENTRY_NUM; ++i) {
		struct pingtrace_map_entry *entry = &value.entries[i];

		if (entry->function_id && entry->ns)
			res.push_back(*entry);
		else
			break;
	}

	return res;
}

} // namespace pingtrace