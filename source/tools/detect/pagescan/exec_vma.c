/*
 * Exec vma scan
 */
#include <linux/kernel-page-flags.h>

#include "pagescan.h"
#include "kernel/mm_types.h"

/*
 * <Exec vma>
 * vma                               pmd (kb) pte (kb) pmd (%)  pte (%)  file
 * 5642c8031000-5642c8181000         0        1212     0.00     100.00   /usr/lib/systemd/systemd
 * 7f8ac626f000-7f8ac6273000         0        16       0.00     100.00   /usr/lib64/libuuid.so.1.3.0
 * [..snip..]
 * 7f8ac8a24000-7f8ac8a46000         0        136      0.00     100.00   /usr/lib64/ld-2.17.so
 * 7fffb1a3d000-7fffb1a3f000         0        4        0.00     100.00   [vdso]
 *
 * <Exec vma>
 * vma                               pmd (kb) pte (kb) pmd (%)  pte (%)  file
 * 400000-124f000                    16384    0        100.00   0.00     /root/hugetext
 * 7f75a3800000-7f75a39c3000         2048     0        100.00   0.00     /usr/lib64/libc-2.17.so
 * 7f75a3c00000-7f75a3c22000         2048     0        100.00   0.00     /usr/lib64/ld-2.17.so
 * 7ffee1fce000-7ffee1fd0000         0        4        0.00     100.00   [vdso]
 */
static void show_exec_vma(struct procmap *procmap)
{
	uint64_t rss, pmd, pte;
	char map_region[33];

	rss = procmap->stat.counter[RSS];
	pmd = procmap->stat.counter[ANONHUGEPAGES] +
		procmap->stat.counter[SHMEMPMDMAPPED] +
		procmap->stat.counter[FILEPMDMAPPED];
	pte = rss - pmd;

	snprintf(map_region, 33, "%lx-%lx", procmap->va_start, procmap->va_end);
	LOG_INFO("%-33s %-8lu %-8lu %-8.2f %-8.2f %s",
			map_region, pmd, pte,
			pmd * 100.0 / rss, pte * 100.0 / rss, procmap->fname);
}

void scan_exec_vma(struct procmap *procmap, int procmap_num)
{
	int procmap_idx;

	LOG_INFO("<Exec vma>\n");
	LOG_INFO("%-33s %-8s %-8s %-8s %-8s %s\n",
			"vma", "pmd (kb)", "pte (kb)", "pmd (%)", "pte (%)", "file");
	for (procmap_idx = 0; procmap_idx < procmap_num; procmap_idx++) {
		if (strstr(procmap[procmap_idx].fname, "[vsyscall]"))
			continue;
		if (!strchr(procmap[procmap_idx].prot, 'x'))
			continue;
		show_exec_vma(&procmap[procmap_idx]);
	}
	LOG_INFO("\n");
}
