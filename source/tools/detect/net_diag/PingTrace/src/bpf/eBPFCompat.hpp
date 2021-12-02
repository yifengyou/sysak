#ifndef EBPF_COMPAT_H
#define EBPF_COMPAT_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace pingtrace {
namespace eBPFCompat {
static void set_filter_id(int id_map, uint32_t id)
{
	uint32_t index = 0;
	bpf_map_update_elem(id_map, &index, &id, 0);
}

static void clear_full_flag(int id_map)
{
	uint32_t index = 1;
	uint32_t flag = 0;

	bpf_map_update_elem(id_map, &index, &flag, 0);
}

static uint32_t get_full_flag(int id_map)
{
	uint32_t index = 1;
	uint32_t flag = 0;

	bpf_map_lookup_elem(id_map, &index, &flag);
	return flag;
}

static void clear_map(int fd)
{
	struct pingtrace_map_key key;
	struct pingtrace_map_key prev_key;
	int ret;

	ret = bpf_map_get_next_key(fd, NULL, &prev_key);
	while (bpf_map_get_next_key(fd, &prev_key, &key) == 0) {
		bpf_map_delete_elem(fd, &prev_key);
		prev_key = key;
	}
	bpf_map_delete_elem(fd, &prev_key);
}
} // namespace eBPFCompat
} // namespace pingtrace

#endif