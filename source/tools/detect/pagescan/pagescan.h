/*
 * Page scan tool
 */
#ifndef _PAGESCAN_UTIL_H
#define _PAGESCAN_UTIL_H

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_ORDER		11
#define PAGE_SHIT		12
#define PAGE_SIZE		(1UL << PAGE_SHIT)
#define HUGE_PAGE_NR		512
#define HUGE_SIZE		(PAGE_SIZE * HUGE_PAGE_NR)
#define BUFF_MAX		4096
#define SIZE_KB			(1UL << 10)
#define SIZE_MB			(1UL << 20)

#define PAGEMAP_PRESENT		63
#define PAGEMAP_PFN_MASK	0x007FFFFFFFFFFFFFUL	/* bits 54:0 */

#define ROUND_UP(x,y)	(((x)+(y)-1)/(y))
#define MIN(a,b)	(((a)<(b))?(a):(b))
#define MAX(a,b)	(((a)>(b))?(a):(b))

#ifdef DEBUG
#define LOG_DEBUG(...)	fprintf(stderr, __VA_ARGS__)
#else
#define LOG_DEBUG(...)	do { } while (0)
#endif /* DEBUG */

#define LOG_INFO(...)	fprintf(stdout, __VA_ARGS__)
#define LOG_WARN(...)	fprintf(stderr, __VA_ARGS__)
#define LOG_ERROR(...)	fprintf(stderr, __VA_ARGS__)

#define MAX_NUMA_NODES	128
extern int nr_numa_node;
int pfn_to_node(unsigned long pfn);

enum {
	SIZE,
	RSS,
	ANONHUGEPAGES,
	SHMEMPMDMAPPED,
	FILEPMDMAPPED,
	MAX_PROCMAP_COUNTER,
};

struct procmap_stat {
	uint64_t counter[MAX_PROCMAP_COUNTER];
#define VMFLAGS_MAX	64
	char     vmflags[VMFLAGS_MAX];
};

#define PROCMAP_SZ	8
struct procmap {
	uint64_t va_start;
	uint64_t va_end;
	uint64_t pgoff;
	uint32_t maj;
	uint32_t min;
	uint32_t ino;
#define PROT_SZ		5
	char     prot[PROT_SZ];
	char     fname[PATH_MAX];
	struct procmap_stat stat;
};

struct buddy_info {
	uint64_t phy_mem_in_bytes;
	void     *bitmap;
	uint64_t bitmap_size;
	size_t   mmap_size;
};
bool buddy_info_test_bit(struct buddy_info *buddy_info, uint64_t pos);

#define KPF_SIZE	8
ssize_t kpageflags_read(void *buf, size_t count, off_t offset);

uintptr_t lookup_kernel_symbol(const char *symbol_name);
ssize_t kcore_readmem(unsigned long kvaddr, void *buf, ssize_t size);
#endif /* _PAGESCAN_UTIL_H */
