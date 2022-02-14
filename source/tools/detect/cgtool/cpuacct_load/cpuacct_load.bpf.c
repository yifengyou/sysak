#include "../cgtoollib_bpf.h"
#include "../cgtool_comm.h"
#include "cpuacct_load.h"

struct bpf_map_def SEC("maps") cpuacct_load_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct cpuacct_load),
	.max_entries = 256,
};

SEC("kprobe/cpuacct_calc_load")
int kprobe_cpuacct_calc_load(struct pt_regs *ctx)
{
	struct cpuacct___AVE *acct = (struct cpuacct___AVE*)PT_REGS_PARM1(ctx);
	int key=0;
	struct cpuacct_load load = {0};
	struct cpuacct_load *load_up;
	struct cgroup___MEMCG *cgrp;
	unsigned int index = 0;
	unsigned int avenrun_n = 0;

	if (bpf_core_read(&cgrp, sizeof(struct cgroup___MEMCG *), &acct->css.cgroup))
			return 0;
	if (bpf_core_read(&key, sizeof(int), &cgrp->id))
			return 0;

	load_up = bpf_map_lookup_elem(&cpuacct_load_hash_map, &key);
	if (load_up != NULL) {
		// update the avenrun
		index = load_up->avenrun_index;
		avenrun_n = load_up->avenrun_n;

		if (index >= AVENRUN_MAX)
			return 0;

		if (bpf_core_read(&load_up->run[index][0], sizeof(unsigned long), &acct->avenrun[0]))
			return 0;
		if (bpf_core_read(&load_up->run[index][1], sizeof(unsigned long), &acct->avenrun[1]))
			return 0;
		if (bpf_core_read(&load_up->run[index][2], sizeof(unsigned long), &acct->avenrun[2]))
			return 0;

		load_up->avenrun_index = (index + 1) % AVENRUN_MAX;
		load_up->avenrun_n = avenrun_n + 1 > AVENRUN_MAX ? AVENRUN_MAX : avenrun_n + 1;
	} else {
		// add new load
		if (bpf_core_read(&load.run[index][0], sizeof(unsigned long), &acct->avenrun[0]))
			return 0;
		if (bpf_core_read(&load.run[index][1], sizeof(unsigned long), &acct->avenrun[1]))
			return 0;
		if (bpf_core_read(&load.run[index][2], sizeof(unsigned long), &acct->avenrun[2]))
			return 0;

		load.avenrun_index = (index + 1) % AVENRUN_MAX;
		load.avenrun_n = avenrun_n + 1 > AVENRUN_MAX ? AVENRUN_MAX : avenrun_n + 1;

		load.knid = get_knid_by_cgroup(cgrp);
		if (load.knid == 0)
			return 0;

		bpf_map_update_elem(&cpuacct_load_hash_map, &key, &load, BPF_ANY);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
