/*
 * Movability scan
 */
#include <linux/kernel-page-flags.h>

#include "pagescan.h"
#include "movability.h"
#include "kernel/mm_types.h"

void scan_movability(struct buddy_info *buddy_info)
{
	struct page pages[HUGE_PAGE_NR];
	uint64_t pageflags[HUGE_PAGE_NR], pageflag;
	uint64_t pfn = 0;
	int page_nr, pages_read;
	int node, idx;
	uint64_t counter[MAX_NUMA_NODES][MAX_MOVABILITY_COUNTER] = {{0}};

	while (1) {
		uint64_t nr_buddy = 0, nr_slab = 0, nr_movable = 0;
		uint64_t nr_pin = 0, nr_p_pin = 0, nr_pin_swch = 0;
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
			pfn += HUGE_PAGE_NR;
			continue;
		}
		pages_read = 1;
#endif

		for (idx = 0; idx < HUGE_PAGE_NR; idx++) {
			pageflag = pageflags[idx];

			if (pageflag & (1UL << KPF_BUDDY)) {
				unsigned int order __attribute__((unused));
				nr_buddy++;
#if defined(KERNEL_3_10)
				order = GET_PAGE_PRIVATE(&pages[idx]);
				if (order > MAX_ORDER) {
					LOG_WARN("invalid page block %lu\n", pfn);
					LOG_WARN("invalid buddy order %u\n", order);
					break;
				}
				page_nr = 1 << order;
				nr_buddy += page_nr - 1;
				idx += page_nr - 1;
#endif
			}
			else if (pageflag & (1 << KPF_SLAB)) {
				nr_slab++;
#if defined(KERNEL_3_10)
				if (!(pageflag & (1 << KPF_COMPOUND_HEAD)))
					continue;

				page_nr = 1 << GET_PAGE_COMPOUND_ORDER(&pages[idx + 1]);
				nr_slab += page_nr - 1;
				idx += page_nr - 1;
#endif
			}
			else if (pageflag & (1 << KPF_LRU)) {
				/* LRU compound page must be THP */
				page_nr = (pageflag & (1 << KPF_COMPOUND_HEAD)) ? HUGE_PAGE_NR : 1;

				if (pageflag & (1 << KPF_ANON)) {  /* PageAnon implies !page_mapping */
					if (pages_read == 0) {
						if (kcore_readmem(PFN_TO_PAGE(pfn), pages,
								sizeof(struct page) * HUGE_PAGE_NR) < 0) {
							LOG_WARN("invalid pfn %lu\n", pfn);
							break;
						}
						pages_read = 1;
					}

					if (get_page_count(&pages[idx], pageflag) >
							get_page_mapcount(&pages[idx], pageflag)) {
						if (buddy_info &&
							buddy_info_test_bit(buddy_info, pfn + idx))
							nr_p_pin += page_nr;

						nr_pin += page_nr;
						if (pageflag & (1 << KPF_SWAPCACHE))
							nr_pin_swch += page_nr;
					} else
						nr_movable += page_nr;
				} else  {
					/* TODO Handling of pinned file page */
					nr_movable += page_nr;
				}

				/* Skip tail pages if any */
				idx += page_nr - 1;
			}
		}

		pfn += HUGE_PAGE_NR;
		node = pfn_to_node(pfn);

		counter[node][BUDDY_PAGES] += nr_buddy;
		counter[node][SLAB_PAGES] += nr_slab;
		counter[node][PIN_PAGES] += nr_pin;
		counter[node][PIN_SWCH_PAGES] += nr_pin_swch;
		counter[node][P_PIN_PAGES] += nr_p_pin;

		if (nr_slab || nr_pin) {
			counter[node][HUGE_UNMOVABLE]++;

			if (nr_slab) {
				counter[node][HUGE_SLAB]++;
				if (nr_buddy)
					counter[node][HUGE_SLAB_FREE]++;
				if (nr_movable)
					counter[node][HUGE_SLAB_MOVE]++;
			}
			if (nr_pin) {
				counter[node][HUGE_PIN]++;
				if (nr_buddy)
					counter[node][HUGE_PIN_FREE]++;
				if (nr_movable)
					counter[node][HUGE_PIN_MOVE]++;
				if (nr_p_pin)
					counter[node][HUGE_P_PIN]++;
			}
		}

		if (nr_buddy) {
			counter[node][HUGE_CANDIDATE]++;

			if (nr_buddy + nr_movable == HUGE_PAGE_NR) {
				if (nr_movable)
					counter[node][HUGE_COMPACT]++;
				else
					counter[node][HUGE_FREE]++;
			}
		}
	}

	LOG_INFO("<Movability>\n");
	print_header();
	PRINT(free_base, BUDDY_PAGES, PAGE_SIZE);
	PRINT(slab_base, SLAB_PAGES, PAGE_SIZE);
	PRINT(pin_base, PIN_PAGES, PAGE_SIZE);
	PRINT(pin_base_swch, PIN_SWCH_PAGES, PAGE_SIZE);
	if (buddy_info)
		PRINT(p_pin_base, P_PIN_PAGES, PAGE_SIZE);
	PRINT(unmovable_huge, HUGE_UNMOVABLE, HUGE_SIZE);
	PRINT(slab_huge, HUGE_SLAB, HUGE_SIZE);
	PRINT(slab_huge_free, HUGE_SLAB_FREE, HUGE_SIZE);
	PRINT(slab_huge_move, HUGE_SLAB_MOVE, HUGE_SIZE);
	PRINT(pin_huge, HUGE_PIN, HUGE_SIZE);
	PRINT(pin_huge_free, HUGE_PIN_FREE, HUGE_SIZE);
	PRINT(pin_huge_move, HUGE_PIN_MOVE, HUGE_SIZE);
	if (buddy_info)
		PRINT(p_pin_huge, HUGE_P_PIN, HUGE_SIZE);
	PRINT(candidate_huge, HUGE_CANDIDATE, HUGE_SIZE);
	PRINT(free_huge, HUGE_FREE, HUGE_SIZE);
	PRINT(compact_huge, HUGE_COMPACT, HUGE_SIZE);
	LOG_INFO("\n");
}

void scan_movability_help(void)
{
	LOG_INFO("<Movability>\n"
		 "Page type explanation:\n"
		 "  free_base            free pages in movable 2M blocks\n"
		 "  slab_base            slab pages\n"
		 "  pin_base             pinned pages\n"
		 "  pin_base_swch        pinned swapcache pages\n"
		 "  p_pin_base           pinned pages of specified process\n"
		 "  unmovable_huge       2M blocks that contain slab or pinned pages\n"
		 "  slab_huge            2M blocks that contain slab pages\n"
		 "  slab_huge_free       2M blocks that contain slab and free pages\n"
		 "  slab_huge_move       2M blocks that contain slab and movable pages\n"
		 "  pin_huge             2M blocks that contain pinned pages\n"
		 "  pin_huge_free        2M blocks that contain pinned and free pages\n"
		 "  pin_huge_move        2M blocks that contain pinned and movable pages\n"
		 "  p_pin_huge           2M blocks that contain pinned pages of specified process\n"
		 "  candidate_huge       2M blocks that contain free pages\n"
		 "  free_huge            2M blocks that only contain free pages\n"
		 "  compact_huge         2M blocks that only contain free and movable pages\n"
		 "\n");
}
