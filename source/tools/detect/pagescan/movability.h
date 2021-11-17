/*
 * Movability definition
 */
#ifndef _MOVABILITY_H
#define _MOVABILITY_H

#include "pagescan.h"

enum {
	BUDDY_PAGES,        /* free pages */
	SLAB_PAGES,         /* slab pages */
	PIN_PAGES,          /* pinned pages */
	PIN_SWCH_PAGES,     /* pinned swapcache pages */
	P_PIN_PAGES,        /* pinned pages of specified process */
	HUGE_UNMOVABLE,     /* 2M blocks that contain slab or pinned pages */
	HUGE_SLAB,          /* 2M blocks that contain slab pages */
	HUGE_SLAB_FREE,     /* 2M blocks that contain slab and free pages */
	HUGE_SLAB_MOVE,     /* 2M blocks that contain slab and movable pages */
	HUGE_PIN,           /* 2M blocks that contain pinned pages */
	HUGE_PIN_FREE,      /* 2M blocks that contain pinned and free pages */
	HUGE_PIN_MOVE,      /* 2M blocks that contain pinned and movable pages */
	HUGE_P_PIN,         /* 2M blocks that contain pinned pages of specified process */
	HUGE_CANDIDATE,     /* 2M blocks that contain free pages */
	HUGE_FREE,          /* 2M blocks that only contain free pages */
	HUGE_COMPACT,       /* 2M blocks that only contain free and movable pages */
	MAX_MOVABILITY_COUNTER,
};

static inline void print_header(void)
{
	int node;

	LOG_INFO("%-16s:", "type");
	for (node = 0; node <= nr_numa_node; node++) {
		char buf[16];

		snprintf(buf, sizeof(buf), "node%d", node);
		LOG_INFO(" %12s", buf);
	}
	LOG_INFO(" %12s\n", "total");
}

static inline void print_body(const char *prefix, unsigned type,
			unsigned long unit,
			uint64_t counter[MAX_NUMA_NODES][MAX_MOVABILITY_COUNTER])
{
	int node;
	uint64_t total = 0;

	LOG_INFO("%-16s:", prefix);
	for (node = 0; node <= nr_numa_node; node++) {
		LOG_INFO(" %11.2fM", counter[node][type] * unit * 1.0 / SIZE_MB);
		total += counter[node][type];
	}
	LOG_INFO(" %11.2fM\n", total * unit * 1.0 / SIZE_MB);
}

#define PRINT(prefix, type, unit) print_body(#prefix, type, unit, counter)
#endif /* _MOVABILITY_H */
