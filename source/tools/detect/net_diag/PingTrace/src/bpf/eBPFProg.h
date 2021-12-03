#ifndef PINGTRACE_EBPF_PROG_H
#define PINGTRACE_EBPF_PROG_H

#include "bpf/eBPFResult.h"
#include "bpf/map_define.h"
#include "common/common.h"
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <vector>

namespace pingtrace {
class BPFProg {
public:
	static int libbpf_print_func(enum libbpf_print_level level, const char *format, va_list args)
	{
		return vfprintf(stderr, format, args);
	}
	static int preinit(bool debug);
	static std::vector<pingtrace_map_entry> query_ts_array(pingtrace_map_key *key, int map_fd);
};

#define BPF_SKELETON_INIT(name, variable, opt)                                                                                                                                                         \
	do {                                                                                                                                                                                           \
		int err;                                                                                                                                                                                   \
																																																	   \
		if (opt->btf_path.empty()) {                                                                                                                                                           \
			variable = name##__open();                                                                                                                                                         \
		} else {                                                                                                                                                                               \
			struct bpf_object_open_opts opts = {};                                                                                                                                             \
			opts.btf_custom_path = (char *)(opt->btf_path.c_str());                                                                                                                            \
			opts.sz = sizeof(struct bpf_object_open_opts);                                                                                                                                     \
			variable = name##__open_opts(&opts);                                                                                                                                               \
		}                                                                                                                                                                                      \
		if (!variable)                                                                                                                                                                             \
			throw ping_exception("Failed to open BPF skeleton, do you have "                                                                                                                       \
								 "capability to use bpf?\n",                                                                                                                                       \
								 errno);                                                                                                                                                           \
		err = name##__load(variable);                                                                                                                                                              \
		if (err)                                                                                                                                                                                   \
		throw ping_exception("Failed to load and verify BPF prog, do you "                                                                                                                     \
							 "have capability to use bpf?\n",                                                                                                                                  \
							 err);                                                                                                                                                             \
		err = name##__attach(variable);                                                                                                                                                            \
		if (err) {                                                                                                                                                                             \
			if (err == -ENOENT)                                                                                                                                                                \
				throw ping_exception("Failed to attach BPF prog, is the debug fs available?\n", err);                                                                                          \
			else                                                                                                                                                                               \
				throw ping_exception("Failed to attach BPF prog, do you have "                                                                                                                 \
									 "capability to use bpf?\n",                                                                                                                               \
									 err);                                                                                                                                                     \
		}                                                                                                                                                                                          \
	}                                                                                                                                                                                              \
	while (0)

class ReceiverBPF {
public:
	virtual ~ReceiverBPF() {}
	virtual eBPFResult query_tx_points(pingtrace_map_key *key) { return {}; }
	virtual eBPFResult query_rx_points(pingtrace_map_key *key) { return {}; }
};

class EcsSenderBPFBase {
public:
	virtual ~EcsSenderBPFBase() {}
	virtual uint64_t query_sched_time() = 0;
	virtual void clear_recorded_sched_time() = 0;
	virtual eBPFResult query_tx_points(pingtrace_map_key *key) = 0;
	virtual eBPFResult query_rx_points(pingtrace_map_key *key) = 0;
};

} // namespace pingtrace

#endif