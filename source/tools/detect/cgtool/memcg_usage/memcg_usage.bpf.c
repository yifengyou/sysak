#include "../cgtoollib_bpf.h"
#include "../cgtool_comm.h"
#include "memcg_usage.h"

struct bpf_map_def SEC("maps") usage_hash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned long),
	.value_size = sizeof(struct memcg_usage),
	.max_entries = 256,
};

SEC("kprobe/mem_cgroup_try_charge")
int kprobe_mem_cgroup_try_charge(struct pt_regs *ctx)
{
	struct mm_struct___MEMCG *mm = (struct mm_struct___MEMCG *)PT_REGS_PARM2(ctx);
	unsigned long pid_tgid = bpf_get_current_pid_tgid();
	struct memcg_usage usage = {0};
	struct memcg_usage *usage_up;
	struct task_struct *tk;

	if (bpf_core_read(&tk, sizeof(struct task_struct *), &mm->owner))
		return 0;

	usage_up = bpf_map_lookup_elem(&usage_hash_map, &pid_tgid);
	if (usage_up == NULL) {
		usage.ptid = pid_tgid;
		if (bpf_core_read(&usage.comm, sizeof(usage.comm), &tk->comm))
			return 0;

		bpf_map_update_elem(&usage_hash_map, &pid_tgid, &usage, BPF_ANY);
	} else {
		if (bpf_core_read(&usage_up->comm, sizeof(usage_up->comm), &tk->comm))
			return 0;
	}

	return 0;
}

SEC("kprobe/mem_cgroup_charge")
int kprobe_mem_cgroup_charge(struct pt_regs *ctx)
{
	struct mm_struct___MEMCG *mm = (struct mm_struct___MEMCG *)PT_REGS_PARM2(ctx);
	unsigned long pid_tgid = bpf_get_current_pid_tgid();
	struct memcg_usage usage = {0};
	struct memcg_usage *usage_up;
	struct task_struct *tk;

	if (bpf_core_read(&tk, sizeof(struct task_struct *), &mm->owner))
		return 0;

	usage_up = bpf_map_lookup_elem(&usage_hash_map, &pid_tgid);
	if (usage_up == NULL) {
		usage.ptid = pid_tgid;
		if (bpf_core_read(&usage.comm, sizeof(usage.comm), &tk->comm))
			return 0;

		bpf_map_update_elem(&usage_hash_map, &pid_tgid, &usage, BPF_ANY);
	} else {
		if (bpf_core_read(&usage_up->comm, sizeof(usage_up->comm), &tk->comm))
			return 0;
	}

	return 0;
}

SEC("kprobe/try_charge")
int kprobe_try_charge(struct pt_regs *ctx)
{
	struct mem_cgroup *memcg = (struct mem_cgroup *)PT_REGS_PARM1(ctx);
	unsigned long pid_tgid = bpf_get_current_pid_tgid();
	struct memcg_usage *usage_up;
	struct cgroup_subsys_state css;
	struct cgroup___MEMCG *cgrp;

	usage_up = bpf_map_lookup_elem(&usage_hash_map, &pid_tgid);
	if (usage_up != NULL) {
		if (bpf_core_read(&css, sizeof(struct cgroup_subsys_state), &memcg->css))
			return 0;
		if (bpf_core_read(&cgrp, sizeof(struct cgroup___MEMCG *), &css.cgroup))
			return 0;
		usage_up->knid = get_knid_by_cgroup(cgrp);
		if (usage_up->knid == 0)
			return 0;

		usage_up->pgsize += (unsigned int)PT_REGS_PARM3(ctx);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
