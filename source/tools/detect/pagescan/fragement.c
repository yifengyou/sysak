/*
 * Fragment scan
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <sys/types.h>

#include "pagescan.h"
#include "bitops.h"

static struct buddy_stat {
	uint64_t	nr[MAX_ORDER];
	uint64_t	used;
} buddy_stat = {{0}, 0};

static inline unsigned long _find_next_bit(const unsigned long *addr1,
			const unsigned long *addr2, unsigned long nbits,
			unsigned long start, unsigned long invert)
{
	unsigned long tmp;

	if (start >= nbits)
		return nbits;

	tmp = addr1[start / BITS_PER_LONG];
	if (addr2)
		tmp &= addr2[start / BITS_PER_LONG];
	tmp ^= invert;

	/* Handle 1st word. */
	tmp &= ~0UL << (start & (BITS_PER_LONG - 1));
	start = (start) & ~(BITS_PER_LONG - 1);

	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr1[start / BITS_PER_LONG];
		if (addr2)
			tmp &= addr2[start / BITS_PER_LONG];
		tmp ^= invert;
	}

	return MIN(start + __ffs(tmp), nbits);
}

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, 0UL);
}

unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	return _find_next_bit(addr, NULL, size, offset, ~0UL);
}

static void buddy_stat_mark_used(uint64_t first, ssize_t len)
{
	uint64_t border, chunk;
	int min, max;

	border = 1UL << (MAX_ORDER - 1);
	while (len > 0) {
		max = ffsll(first | border) - 1;
		min = fls64(len) - 1;

		if (max < min)
			min = max;
		chunk = 1UL << min;

		buddy_stat.nr[min]++;

		len -= chunk;
		first += chunk;
	}
}

static void buddy_stat_generate(struct buddy_info *buddy_info)
{
	void *bitmap = buddy_info->bitmap;
	uint64_t max = buddy_info->bitmap_size;
	uint64_t first, i;
	ssize_t len;

	i = find_next_bit(bitmap, max, 0);
	while (i < max) {
		first = i;
		i = find_next_zero_bit(bitmap, max, i);
		len = i - first;
		buddy_stat.used += len;
		if (len > 1)
			buddy_stat_mark_used(first, len);
		else
			buddy_stat.nr[0]++;
		if (i < max)
			i = find_next_bit(bitmap, max, i);
	}
}

#define TOTAL_SIGNS 50
static void buddy_stat_show()
{
	int order, pages, idx, signs;
	float percent;

	if (buddy_stat.used == 0) {
		LOG_INFO("No physical pages used\n");
		return;
	}

	LOG_INFO("<Fragments>\n");
	/*
	 * order pages        percent
	 * 0     1658         5.61%	[#                               ]
	 * 1     684          2.32%	[                                ]
	 * 2     452          1.53%	[                                ]
	 * ...
	 * 8     0            0.00%	[                                ]
	 * 9     15872        53.75%	[#################               ]
	 * 10    10240        34.68%	[###########                     ]
	 */
	LOG_INFO("%-5s %-12s %-8s\n", "order", "pages", "percent");
	for (order = 0; order < MAX_ORDER; order++) {
		pages = (1 << order) * buddy_stat.nr[order];
		percent = pages * 100.0 / buddy_stat.used;
		signs = percent * TOTAL_SIGNS / 100 + 0.5;
		LOG_INFO("%-5u %-12u %-.2f%%\t", order, pages,
				pages * 100.0 / buddy_stat.used);

		LOG_INFO("[");
		for (idx = 0; idx < signs; idx++)
			LOG_INFO("#");
		for (; idx < TOTAL_SIGNS; idx++)
			LOG_INFO(" ");
		LOG_INFO("]\n");
	}

	LOG_INFO("total pages = %" PRIu64 "\n", buddy_stat.used);
	LOG_INFO("\n");
}


void scan_fragment(struct buddy_info *buddy_info)
{
	if (!buddy_info) {
		LOG_ERROR("no pids are provided\n");
		return;
	}
	buddy_stat_generate(buddy_info);
	buddy_stat_show();
}
