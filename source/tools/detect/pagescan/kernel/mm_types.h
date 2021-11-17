#ifndef _MM_TYPES_H
#define _MM_TYPES_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

extern unsigned long vmemmap_base;
extern unsigned long page_offset_base;

#define PAGE_STRUCT_SIZE	64
#define PAGE_MAPPING_ANON	0x1

#define PFN_TO_VIRT(pfn)	(page_offset_base + ((pfn) << PAGE_SHIT))
#define PFN_TO_PAGE(pfn)	(vmemmap_base + (pfn) * PAGE_STRUCT_SIZE)

#define GET_PAGE_FIELD(pg, field)	(((struct page *)pg)->field)

#if defined(KERNEL_3_10)
struct page {
	unsigned long flags;
	uintptr_t mapping;
	struct {
		union {
			unsigned long index;
			uintptr_t freelist;
			bool pfmemalloc;
			uintptr_t pmd_huge_pte;
		};
		union {
			unsigned long counters;
			struct {
				union {
					int _mapcount;
					struct {
						unsigned int inuse : 16;
						unsigned int objects : 15;
						unsigned int frozen : 1;
					};
					int units;
				};
				int _count;
			};
		};
	};
	union {
		uintptr_t lru[2];
		struct {
			uintptr_t next;
			int pages;
			int pobjects;
		};
		uintptr_t list[2];
		uintptr_t slab_page;
	};
	union {
		unsigned long private;
		unsigned int ptl;
		uintptr_t slab_cache;
		uintptr_t first_page;
	};
};

struct kmem_cache {
	uintptr_t cpu_slab;
	unsigned long flags;
	unsigned long min_partial;
	int size;
	int object_size;
	int offset;
	int cpu_partial;
	unsigned long oo;
	unsigned long max;
	unsigned long min;
	unsigned int allocflags;
	int refcount;
	uintptr_t ctor;
	int inuse;
	int align;
	int reserved;
	unsigned int padding1;	/* explicitly add 4 padding */
	uintptr_t name;
	uintptr_t list[2];
	uint64_t kobj[8];
	uintptr_t memcg_params;
	int max_attr_size;
	int remote_node_defrag_ratio;
	uintptr_t node[1024];
};
#elif defined(KERNEL_4_9)
struct page {
	unsigned long flags;
	union {
		uintptr_t mapping;
		uintptr_t s_mem;
		int compound_mapcount;
	};
	union {
		unsigned long index;
		uintptr_t freelist;
	};
	union {
		unsigned long counters;
		struct {
			union {
				int _mapcount;
				unsigned int active;
				struct {
					unsigned int inuse : 16;
					unsigned int objects : 15;
					unsigned int frozen : 1;
				};
				int units;
			};
			int _refcount;
		};
	};
	union {
		uintptr_t lru[2];
		uintptr_t pgmap;
		struct {
			uintptr_t next;
			int pages;
			int pobjects;
		};
		uintptr_t callback_head[2];
		struct {
			unsigned long compound_head;
			unsigned int compound_dtor;
			unsigned int compound_order;
		};
		struct {
			unsigned long __pad;
			uintptr_t pmd_huge_pte;
		};
	};
	union {
		unsigned long private;
		unsigned int ptl;
		uintptr_t slab_cache;
	};
	uintptr_t mem_cgroup;
};

struct kmem_cache {
	uintptr_t cpu_slab;
	unsigned long flags;
	unsigned long min_partial;
	unsigned int nice;
	int size;
	int object_size;
	int offset;
	unsigned int cpu_partial;
	unsigned int padding1;	/* explicitly add 4 padding */
	unsigned long oo;
	unsigned long max;
	unsigned long min;
	unsigned int allocflags;
	int refcount;
	uintptr_t ctor;
	int inuse;
	int align;
	int reserved;
	uintptr_t name;
	uintptr_t list[2];
	int red_left_pad;
	unsigned int padding2;	/* explicitly add 4 padding */
	uint64_t kobj[8];
	uint64_t memcg_params[5];
	int max_attr_size;
	unsigned int padding3;	/* explicitly add 4 padding */
	uintptr_t memcg_kset;
	int remote_node_defrag_ratio;
	unsigned int padding4;	/* explicitly add 4 padding */
	uintptr_t node[1024];
};
#elif defined(KERNEL_4_19)
struct page {
	unsigned long flags;
	union {
		struct {
			uintptr_t lru[2];
			uintptr_t mapping;
			unsigned long index;
			unsigned long private;
		};
		struct {
			union {
				uintptr_t slab_list[2];
				struct {
					uintptr_t next;
					int pages;
					int pobjects;
				};
			};
			uintptr_t slab_cache;
			uintptr_t freelist;
			union {
				uintptr_t s_mem;
				unsigned long counters;
				struct {
					unsigned int inuse : 16;
					unsigned int objects : 15;
					unsigned int frozen : 1;
				};
			};
		};
		struct {
			unsigned long compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			int compound_mapcount;
		};
		struct {
			unsigned long _compound_pad_1;
			unsigned long _compound_pad_2;
			uintptr_t deferred_list[2];
		};
		struct {
			unsigned long _pt_pad_1;
			uintptr_t pmd_huge_pte;
			unsigned long _pt_pad_2;
			union {
				uintptr_t pt_mm;
				int pt_frag_refcount;
			};
			unsigned int ptl;
		};
		struct {
			uintptr_t pgmap;
			unsigned long hmm_data;
			unsigned long _zd_pad_1;
		};
		uintptr_t callback_head[2];
	};
	union {
		int _mapcount;
		unsigned int page_type;
		unsigned int active;
		int units;
	};
	int _refcount;
	uintptr_t mem_cgroup;
};

struct kmem_cache {
	uintptr_t cpu_slab;
	unsigned int flags;
	unsigned int padding1;	/* explicitly add 4 padding */
	unsigned long min_partial;
	unsigned int size;
	unsigned int object_size;
	unsigned int offset;
	unsigned int cpu_partial;
	unsigned int oo;
	unsigned int max;
	unsigned int min;
	unsigned int allocflags;
	int refcount;
	unsigned int padding2;	/* explicitly add 4 padding */
	uintptr_t ctor;
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	unsigned int padding3;	/* explicitly add 4 padding */
	uintptr_t name;
	uintptr_t list[2];
	uint64_t kobj[8];
	uint64_t kobj_remove_work[4];
	uint64_t memcg_params[11];
	unsigned int max_attr_size;
	unsigned int padding4;	/* explicitly add 4 padding */
	uintptr_t memcg_kset;
	unsigned int remote_node_defrag_ratio;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int padding5;	/* explicitly add 4 padding */
	uintptr_t node[64];
};
#endif

#define GET_PAGE_FLAGS(pg)		GET_PAGE_FIELD(pg, flags)
#define GET_PAGE_MAPPING(pg)		GET_PAGE_FIELD(pg, mapping)
#define GET_PAGE_PRIVATE(pg)		GET_PAGE_FIELD(pg, private)
#define GET_PAGE_SLAB_CACHE(pg)		GET_PAGE_FIELD(pg, slab_cache)
#define GET_PAGE_MAPCOUNT(pg)		(GET_PAGE_FIELD(pg, _mapcount) + 1)

#if defined(KERNEL_3_10)
#define GET_PAGE_REFCOUNT(pg)		GET_PAGE_FIELD(pg, _count)
#define GET_PAGE_COMPOUND_ORDER(pg)	GET_PAGE_FIELD(pg, lru[1])

/*
 * get_page_count() for kernel 3.10 only works for single page and compound
 * head page, but not for compound tail page.
 */
static inline unsigned int get_page_count(struct page *page,
						uint64_t pageflags)
{
	assert(!(pageflags & (1 << KPF_COMPOUND_TAIL)));

	return GET_PAGE_REFCOUNT(page);
}
static inline unsigned int get_page_mapcount(struct page *page,
						uint64_t pageflags)
{
	return GET_PAGE_MAPCOUNT(page);
}
#elif defined(KERNEL_4_9) || defined(KERNEL_4_19)
#define GET_PAGE_REFCOUNT(pg)		GET_PAGE_FIELD(pg, _refcount)
#define GET_PAGE_COMPOUND_HEAD(pg)	GET_PAGE_FIELD(pg, compound_head)
#define GET_PAGE_COMPOUND_ORDER(pg)	GET_PAGE_FIELD(pg, compound_order)
#define GET_PAGE_COMPOUND_MAPCOUNT(pg)	(GET_PAGE_FIELD(pg, compound_mapcount) + 1)

static inline unsigned int get_page_count(struct page *page,
						uint64_t pageflags)
{
	unsigned long head;
	unsigned long compound_head_addr;
	struct page compound_page;

	head = GET_PAGE_COMPOUND_HEAD(page);

	if (head & 1) {
		compound_head_addr = (unsigned long)(head - 1);
		kcore_readmem(compound_head_addr, &compound_page,
				sizeof(struct page));
		return GET_PAGE_REFCOUNT(&compound_page);
	}

	return GET_PAGE_REFCOUNT(page);
}
static inline unsigned int get_page_mapcount(struct page *page,
						uint64_t pageflags)
{
	unsigned long head;
	unsigned long compound_head_addr;
	struct page compound_pages[2];

	/* FIXME __page_mapcount sanity check: PageAnon, PageHuge */
	if (pageflags & ((1 << KPF_COMPOUND_HEAD) | (1 << KPF_COMPOUND_TAIL))) {
		head = GET_PAGE_COMPOUND_HEAD(page);

		if (head & 1) {	/* tail pages */
			compound_head_addr = (unsigned long)(head - 1);
			kcore_readmem(compound_head_addr, compound_pages,
					sizeof(struct page) * 2);
		} else		/* head page */
			memcpy(compound_pages, page, sizeof(compound_pages));
		/* FIXME PageDoubleMap */
		return GET_PAGE_MAPCOUNT(page) + GET_PAGE_COMPOUND_MAPCOUNT(&compound_pages[1]);
	}

	return GET_PAGE_MAPCOUNT(page);
}
#endif
#endif /* _MM_TYPES_H */
