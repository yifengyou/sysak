Page Scan Tool
==============

This tool is introduced to scan memory at page granularity, in different
dimensions, such as fragment, movability, zero subpages, and etc.

This tool supports only kernel 3.10, 4.9 and 4.19 at present.

Fragment
========
This feature scans the external fragmentation of specified pid(s), through
gathering and couning the physical page frames mapped by the specified pid(s)
in the form of continuous blocks.

The sample is as follows.

$ sudo ./pagescan -p 1 -f
pid     cmdline
1       /usr/lib/systemd/systemd

<Fragments>
order pages        percent
0     1290         40.59%       [####################                              ]
1     160          5.03%        [###                                               ]
2     136          4.28%        [##                                                ]
3     56           1.76%        [#                                                 ]
4     0            0.00%        [                                                  ]
5     0            0.00%        [                                                  ]
6     0            0.00%        [                                                  ]
7     0            0.00%        [                                                  ]
8     0            0.00%        [                                                  ]
9     1536         48.33%       [########################                          ]
10    0            0.00%        [                                                  ]
total pages = 3178

The number of '#' indicates the proportion of each page order composed of
continuous physical page frames.

Movability
==========
This feature scans the movability of each physical page frame and
corresponding page block (usually 2M). The movability includes free,
movable (e.g., LRU pages), and unmovable (e.g., slab and pined pages).

This feature supports both scan of specified pid(s) and the whole system.

Page type explanation
---------------------
free_base            free pages in movable 2M blocks
slab_base            slab pages
pin_base             pinned pages
pin_base_swch        pinned swapcache pages
p_pin_base           pinned pages of specified process
unmovable_huge       2M blocks that contain slab or pinned pages
slab_huge            2M blocks that contain slab pages
slab_huge_free       2M blocks that contain slab and free pages
slab_huge_move       2M blocks that contain slab and movable pages
pin_huge             2M blocks that contain pinned pages
pin_huge_free        2M blocks that contain pinned and free pages
pin_huge_move        2M blocks that contain pinned and movable pages
p_pin_huge           2M blocks that contain pinned pages of specified process
candidate_huge       2M blocks that contain free pages
free_huge            2M blocks that only contain free pages
compact_huge         2M blocks that only contain free and movable pages

The sample is as follows.

$ sudo ./pagescan -m
<Movability>
type            :        node0        total
free_base       :   315243.31M   315243.31M
slab_base       :     2434.37M     2434.37M
pin_base        :       64.00M       64.00M
pin_base_swch   :        0.00M        0.00M
unmovable_huge  :     8502.00M     8502.00M
slab_huge       :     8436.00M     8436.00M
slab_huge_free  :     7740.00M     7740.00M
slab_huge_move  :     1852.00M     1852.00M
pin_huge        :       66.00M       66.00M
pin_huge_free   :        2.00M        2.00M
pin_huge_move   :        2.00M        2.00M
candidate_huge  :   350304.00M   350304.00M
free_huge       :   226582.00M   226582.00M
compact_huge    :    94914.00M    94914.00M

Slab Movability
===============
This feature scans the page blocks polluted by specified slab(s), i.e., 2M
blocks that contain the specified slab(s).

The sample is as follows.

$ sudo ./pagescan -s dentry,inode_cache
kmem_cache: name: dentry, addr: 0xffff9e50ee9a2580
kmem_cache: name: inode_cache, addr: 0xffff9e50ee9a2700

<SlabMovability>
type            :        node0        total
slab_base       :      311.38M      311.38M
slab_huge       :     5578.00M     5578.00M
slab_huge_free  :     5562.00M     5562.00M
slab_huge_move  :        0.00M        0.00M

Zero Subpages
=============
This feature scans the zero subpages in 2M virtual space and THP,
respectively.

This feature supports both scan of specified pid(s) and the whole system.

Zero subpages in 2M virtual space
---------------------------------
We use "base zero" to refer to base pages (usually 4K) in continuous 2M virtual
memory that are not mapped by physical memory. This indicator can be used to
estimate the memory waste when enabling THP.

Zero subpages in THP
--------------------
We use "thp zero" to refer to base pages (usually 4K) with zero content in THP,
which can be used to estimate the memory waste caused by THP.

It's worth noting that readonly zero THP is a separate output that represents
the THP page fault triggered by read.

The sample is as follows.

$ sudo ./pagescan -p 1 -z
pid     cmdline
1       /usr/lib/systemd/systemd

<Zero subpages>
zero_subpages   huge_pages   percent  waste
base zero:
[     0,     1) 3            100.00%  0.00%     [                                                  ]
[     1,     2) 0             0.00%  0.00%      [                                                  ]
[     2,     4) 0             0.00%  0.00%      [                                                  ]
[     4,     8) 0             0.00%  0.00%      [                                                  ]
[     8,    16) 0             0.00%  0.00%      [                                                  ]
[    16,    32) 0             0.00%  0.00%      [                                                  ]
[    32,    64) 0             0.00%  0.00%      [                                                  ]
[    64,   128) 0             0.00%  0.00%      [                                                  ]
[   128,   256) 0             0.00%  0.00%      [                                                  ]
[   256,   512) 0             0.00%  0.00%      [                                                  ]
total zero subpages = 0.00%

thp zero:
[     0,     1) 0             0.00%  0.00%      [                                                  ]
[     1,     2) 0             0.00%  0.00%      [                                                  ]
[     2,     4) 0             0.00%  0.00%      [                                                  ]
[     4,     8) 0             0.00%  0.00%      [                                                  ]
[     8,    16) 0             0.00%  0.00%      [                                                  ]
[    16,    32) 1            33.33%  2.02%      [#                                                 ]
[    32,    64) 0             0.00%  0.00%      [                                                  ]
[    64,   128) 2            66.67%  9.38%      [#####                                             ]
[   128,   256) 0             0.00%  0.00%      [                                                  ]
[   256,   512) 0             0.00%  0.00%      [                                                  ]
total zero subpages = 11.39%
total readonly zero THP: 0

Among the output, huge_pages indicates the number of 2M block that contains
zero subpages, percent indicates the percentage of 2M block containing zero
subpages against total 2M blocks, and waste represents the percentage of
zero pages in total RSS.

Executable VMA
==============
This feature scans the memory maps of code segments of specified process, and
count the PMD and PTE mappings.

In the current implementation, PMD mappings are counted according to the sum
of AnonHugepages, ShmemPMDMapped, and FilepMDMapped (if any) in the
/proc/pid/smaps file. The PTE mappings are obtained using RSS - PMD mappings
as a temporary schema.
