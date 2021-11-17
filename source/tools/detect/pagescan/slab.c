/*
 * Slab scan
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <limits.h>
#include <linux/kernel-page-flags.h>
#include <stddef.h>
#include <unistd.h>

#include "pagescan.h"
#include "movability.h"
#include "kernel/mm_types.h"

#define MAX_SLAB 255
static char *slab_names[MAX_SLAB + 1];
static uintptr_t slab_addrs[MAX_SLAB + 1];

#define offsetof_list_in_kmem_cache offsetof(struct kmem_cache, list)
#define offsetof_name_in_kmem_cache offsetof(struct kmem_cache, name)

static int parse_slab_names(char *slabs)
{
	char **pos, *this, *sp = NULL;
	char syspath[PATH_MAX];

	pos = slab_names;
	for (this = strtok_r(slabs, ",", &sp);
			this && pos - slab_names < MAX_SLAB;
			this = strtok_r(NULL, ",", &sp)) {
		snprintf(syspath, PATH_MAX, "/sys/kernel/slab/%s", this);
		if (access(syspath, F_OK) < 0) {
			LOG_ERROR("slab %s does not exist\n", this);
			continue;
		}
		*pos++ = this;
	}
	*pos = NULL;

	return !!slab_names[0];
}

static int lookup_slab_addrs(void)
{
	uintptr_t p_slab_caches, p_list_head;
	uintptr_t p_kmem_cache, pp_kmem_cache_name, p_kmem_cache_name;
	char kmem_cache_name[NAME_MAX];
	int i;

	p_slab_caches = lookup_kernel_symbol("slab_caches");
	if (p_slab_caches == -1UL)
		return -1;

	if (kcore_readmem(p_slab_caches, &p_list_head, 8) < 8)
		return -1;

	while (p_list_head != p_slab_caches) {
		p_kmem_cache = p_list_head - offsetof_list_in_kmem_cache;
		pp_kmem_cache_name = p_kmem_cache + offsetof_name_in_kmem_cache;
		kcore_readmem(pp_kmem_cache_name, &p_kmem_cache_name, 8);
		kcore_readmem(p_kmem_cache_name, kmem_cache_name, NAME_MAX);

		for (i = 0; i < MAX_SLAB && slab_names[i]; i++) {
			if (!strncmp(kmem_cache_name, slab_names[i],
						strlen(slab_names[i]))) {
				slab_addrs[i] = p_kmem_cache;
				break;
			}
		}

		kcore_readmem(p_list_head, &p_list_head, 8);
	}

	for (i = 0; i < MAX_SLAB && slab_names[i]; i++)
		LOG_INFO("kmem_cache: name: %s, addr: %#lx\n",
				slab_names[i], slab_addrs[i]);
	LOG_INFO("\n");

	return 0;
}

void scan_slabs(char *slabs)
{
	struct page pages[HUGE_PAGE_NR];
	uint64_t pageflags[HUGE_PAGE_NR], pageflag;
	uint64_t pfn = 0;
	int page_nr, pages_read;
	int node, i, j;
	uint64_t counter[MAX_NUMA_NODES][MAX_MOVABILITY_COUNTER] = {{0}};

	if (!parse_slab_names(slabs)) {
		LOG_ERROR("no valid slabs\n");
		return;
	}

	if (lookup_slab_addrs() < 0)
		return;

	while (1) {
		uint64_t nr_buddy = 0, nr_slab = 0, nr_movable = 0;
		pages_read = 0;

		if (kpageflags_read(pageflags, KPF_SIZE * HUGE_PAGE_NR,
				KPF_SIZE * pfn) != KPF_SIZE * HUGE_PAGE_NR)
			break;

#if defined(KERNEL_3_10)
		/*
		 * Caveats on high order pages: page->_count will only be set
		 * -1 on the head page; SLUB/SLQB do the same for PG_slab;
		 * SLOB won't set PG_slab at all on compound pages.
		 *
		 * See stable_page_flags().
		 */
		if (kcore_readmem(PFN_TO_PAGE(pfn), pages,
				sizeof(struct page) * HUGE_PAGE_NR) < 0) {
			LOG_WARN("invalid pfn %lu\n", pfn);
			continue;
		}
		pages_read = 1;
#endif

		for (i = 0; i < HUGE_PAGE_NR; i++) {
			page_nr = 1;
			pageflag = pageflags[i];

			if (pageflag & (1 << KPF_BUDDY)) {
				nr_buddy++;
#if defined(KERNEL_3_10)
				page_nr = 1 << GET_PAGE_PRIVATE(&pages[i]);
				nr_buddy += page_nr - 1;
				i += page_nr - 1;
#endif
				continue;
			}

			if (!(pageflag & (1 << KPF_LRU)) &&
					!(pageflag & (1 << KPF_SLAB)))
				continue;

			if (pages_read == 0) {
				if (kcore_readmem(PFN_TO_PAGE(pfn), pages,
						sizeof(struct page) * HUGE_PAGE_NR) < 0) {
					LOG_WARN("invalid pfn %lu\n", pfn);
					break;
				}
				pages_read = 1;
			}

			if (pageflag & (1 << KPF_LRU)) {
				/* LRU compound page must be THP */
				page_nr = (pageflag & (1 << KPF_COMPOUND_HEAD)) ? HUGE_PAGE_NR : 1;

				if (pageflag & (1 << KPF_ANON)) {  /* PageAnon implies !page_mapping */
					if (get_page_count(&pages[i], pageflag) ==
						get_page_mapcount(&pages[i], pageflag))
						nr_movable += page_nr;
				} else {
					/* TODO Handling of pinned file page */
					nr_movable += page_nr;
				}

				/* Skip tail pages if any */
				i += page_nr - 1;
				continue;
			}

			assert(pageflag & (1 << KPF_SLAB) &&
				!(pageflag & (1 << KPF_COMPOUND_TAIL)));

			/* KPF_COMPOUND_HEAD is set for slab with positive order */
			if (pageflag & (1 << KPF_COMPOUND_HEAD))
				page_nr = 1 << GET_PAGE_COMPOUND_ORDER(&pages[i + 1]);

			for (j = 0; j < MAX_SLAB && slab_names[j]; j++) {
				if (slab_addrs[j] == GET_PAGE_SLAB_CACHE(&pages[i])) {
					nr_slab += page_nr;
					break;
				}
			}

			/* Skip tail pages if any */
			i += page_nr - 1;
		}

		pfn += HUGE_PAGE_NR;

		node = pfn_to_node(pfn);
		if (nr_slab) {
			counter[node][SLAB_PAGES] += nr_slab;
			counter[node][HUGE_SLAB]++;
			if (nr_buddy)
				counter[node][HUGE_SLAB_FREE]++;
			if (nr_movable)
				counter[node][HUGE_SLAB_MOVE]++;
		}
	}

	LOG_INFO("<SlabMovability>\n");
	print_header();
	PRINT(slab_base, SLAB_PAGES, PAGE_SIZE);
	PRINT(slab_huge, HUGE_SLAB, HUGE_SIZE);
	PRINT(slab_huge_free, HUGE_SLAB_FREE, HUGE_SIZE);
	PRINT(slab_huge_move, HUGE_SLAB_MOVE, HUGE_SIZE);
	LOG_INFO("\n");
}
