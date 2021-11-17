/*
 * Zero subpages scan
 */
#include <linux/kernel-page-flags.h>
#include <stdbool.h>

#include "pagescan.h"
#include "kernel/mm_types.h"

/*
 * KPF_ZERO_PAGE is introduced in v4.0-rc1, and define it if not present,
 * in order to fix potential building error.
 */
#ifndef KPF_ZERO_PAGE
#define KPF_ZERO_PAGE		24
#endif

static struct huge_stat {
	uint64_t zero_pages_base[HUGE_PAGE_NR];     /* at most 511 not present pages */
	uint64_t total_huge_pages_base;
	uint64_t zero_pages_thp[HUGE_PAGE_NR + 1];  /* at most 512 zero subpages */
	uint64_t total_huge_pages_thp;
	uint64_t total_thp_readonly_zero;
	uint64_t total_thp_deferred_split;
	uint64_t total_rss_pages;
} huge_stat = {{0}, 0, {0}, 0, 0, 0, 0};

#define TOTAL_SIGNS 50
static void huge_stat_dump(int base)
{
	uint64_t total_huge_pages, total_zero_pages = 0;
	uint64_t subtotal_huge, subtotal_zero;
	int zero_idx, zero_next, idx, signs;
	float waste;

	total_huge_pages = base ? huge_stat.total_huge_pages_base :
					huge_stat.total_huge_pages_thp;

	LOG_INFO("%s:\n", base ? "base zero" : "thp zero");
	if (!total_huge_pages) {
		LOG_ERROR("no huge pages\n\n");
		return;
	}
	LOG_INFO("%-15s %-12s %-8s %-8s\n", "zero_subpages", "huge_pages",
						"percent", "waste");

	for (zero_idx = 0; zero_idx < HUGE_PAGE_NR; zero_idx = zero_next) {
		subtotal_huge = 0;
		subtotal_zero = 0;
		zero_next = zero_idx ? zero_idx * 2 : 1;
		if (!base && zero_next == HUGE_PAGE_NR)
			zero_next++;
		for (idx = zero_idx; idx < zero_next; idx++) {
			int zero_pages = base ? huge_stat.zero_pages_base[idx] :
						huge_stat.zero_pages_thp[idx];
			subtotal_huge += zero_pages;
			subtotal_zero += zero_pages * idx;
		}
		waste = subtotal_zero * 100.0 / (total_huge_pages * HUGE_PAGE_NR);
		signs = waste * TOTAL_SIGNS / 100 + 0.5;
		LOG_INFO("[%6u,%6u) %-12lu %5.2f%% %5.2f%%\t",
				zero_idx, zero_next, subtotal_huge,
				subtotal_huge * 100.0 / total_huge_pages,
				waste);

		LOG_INFO("[");
		for (idx = 0; idx < signs; idx++)
			LOG_INFO("#");
		for (; idx < TOTAL_SIGNS; idx++)
			LOG_INFO(" ");
		LOG_INFO("]\n");
		total_zero_pages += subtotal_zero;
	}
	if (!base)
		LOG_INFO("total thp pages = %lu\n", huge_stat.total_huge_pages_thp);
	LOG_INFO("total zero subpages (of huge) = %.2f%%\n",
		total_zero_pages * 100.0 / (total_huge_pages * HUGE_PAGE_NR));
	if (base)
		LOG_INFO("total RSS pages = %lu\n", huge_stat.total_rss_pages);
	if (!base && huge_stat.total_rss_pages)
		LOG_INFO("total zero subpages (of RSS) = %.2f%%\n",
			total_zero_pages * 100.0 / (huge_stat.total_rss_pages));
	LOG_INFO("\n");
}

static void scan_zero_subpages_in_thp(struct buddy_info *buddy_info)
{
	uint64_t pageflag;
	uint64_t contents[PAGE_SIZE / sizeof(uint64_t)];
	unsigned long pfn = 0;
	int zero_subpages_idx, i, j;

	while (1) {
		if (kpageflags_read(&pageflag, KPF_SIZE,
					KPF_SIZE * pfn) != KPF_SIZE)
			break;

		if (buddy_info && !(buddy_info_test_bit(buddy_info, pfn)))
			goto next;

		/* TODO Handling of file THP */
		if (!(pageflag & (1 << KPF_THP)) ||
				!(pageflag & (1 << KPF_ANON)))
			goto next;

		if (pageflag & (1 << KPF_ZERO_PAGE)) {
			huge_stat.total_thp_readonly_zero++;
			goto next;
		}

		zero_subpages_idx = 0;
		for (i = 0; i < HUGE_PAGE_NR; i++) {
			if (kcore_readmem(PFN_TO_VIRT(pfn + i), contents, PAGE_SIZE) < 0) {
				LOG_WARN("invalid pfn %lu\n", pfn + i);
				break;
			}

			for (j = 0; j < PAGE_SIZE / sizeof(uint64_t); j++) {
				if (contents[j])
					break;
			}

			if (j == PAGE_SIZE / sizeof(uint64_t))
				zero_subpages_idx++;
		}
		huge_stat.zero_pages_thp[zero_subpages_idx]++;
		huge_stat.total_huge_pages_thp++;

next:
		pfn += HUGE_PAGE_NR;
	}
}

/*
 * The parameter @idx indicates the page index in the round scan whose
 * maximum index is @end.  And the parameter @raw_pfn is natively read
 * from pagemap.
 */
void scan_zero_subpages_in_base(uint64_t raw_pfn, int idx, int end)
{
	static int nr_scan = 0;
	static int nr_not_present = 0;
	static bool pageflag_read = false;
	static uint64_t thp_pfn = 0;
	static uint64_t last_thp_pfn = 0;

	/* A new round */
	if (idx == 0) {
		nr_scan = 0;
		nr_not_present = 0;
		pageflag_read = false;
		thp_pfn = 0;
	}

	nr_scan++;
	if (!(raw_pfn & (1UL << PAGEMAP_PRESENT)))
		nr_not_present++;
	else {
		huge_stat.total_rss_pages++;

		if (!pageflag_read) {
			uint64_t pageflag;
			uint64_t pfn = raw_pfn & PAGEMAP_PFN_MASK;

			if (kpageflags_read(&pageflag, KPF_SIZE,
						KPF_SIZE * pfn) == KPF_SIZE)
				if (pageflag & (1UL << KPF_THP))
					thp_pfn = pfn & ~(HUGE_PAGE_NR - 1);

			pageflag_read = true;
		}
	}

	/* End of this round */
	if (idx == end - 1) {
		if (thp_pfn &&
				last_thp_pfn != thp_pfn &&  /* not accounted */
				(nr_scan < HUGE_PAGE_NR ||  /* partially munmap */
				 nr_not_present))           /* MADV_DONTNEED */
			huge_stat.total_thp_deferred_split++;

		if (!thp_pfn &&
				nr_scan == HUGE_PAGE_NR &&  /* 2M page block */
				nr_not_present < nr_scan) { /* at least 1 page present */
			huge_stat.zero_pages_base[nr_not_present]++;
			huge_stat.total_huge_pages_base++;
		}

		if (thp_pfn)
			last_thp_pfn = thp_pfn;
	}
}

void scan_zero_subpages(struct buddy_info *buddy_info)
{
	scan_zero_subpages_in_thp(buddy_info);

	LOG_INFO("<Zero subpages>\n");
	if (buddy_info)
		huge_stat_dump(1);
	huge_stat_dump(0);
	LOG_INFO("total deferred split THP: %lu\n",
			huge_stat.total_thp_deferred_split);
	LOG_INFO("total readonly zero THP:  %lu\n",
			huge_stat.total_thp_readonly_zero);
}
