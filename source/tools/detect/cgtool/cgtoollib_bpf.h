#ifndef __CGTRACELIB_BPF_H
#define __CGTRACELIB_BPF_H

#include <linux/version.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cgtool_comm.h"

#define BPF_ANY 0
#define NULL ((void*)0)

static u64 get_knid_by_cgroup(struct cgroup___MEMCG *cgrp)
{
	struct kernfs_node___419 *node;
	union kernfs_node_id id;
	unsigned int knid;

	if (bpf_core_read(&node, sizeof(struct kernfs_node___419 *), &cgrp->kn))
		return 0;
	if (bpf_core_read(&id, sizeof(union kernfs_node_id), &node->id))
		return 0;
	if (bpf_core_read(&knid, sizeof(u64), &id.id))
		return 0;

	return knid;
}

#endif
