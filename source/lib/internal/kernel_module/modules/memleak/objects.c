#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/kallsyms.h>
#include <linux/atomic.h>

#include "mem.h"

static int rate = 75;

static int compute_valid_num(unsigned char *src, int size)
{
	int i ;
	int valid = 0;

	for (i = 0; i < size; i++) {
		if (src[i] == 0x00 || src[i] == 0xFF)
			continue;
		valid++;
	}
	return valid;
}

static int compare_one_object(struct object *object, unsigned char *dst, int size)
{
	int i ;
	int valid_num = 0;
	unsigned char *src = (unsigned char *)object->ptr;

	for (i = 0; i < size; i++) {

		if (src[i] == 0x00 || src[i] == 0xFF)
			continue;
		if (src[i] == dst[i])
			valid_num++;
	}

	return ((valid_num * 100) >= (object->valid_byte * rate));
}

static int find_similar_object(struct object_info *info, struct object *object, unsigned long long  *arr, int num)
{
	int i, j;
	int valid = 0;
	int ret = 0;
	int max = 0;
	struct object tmp;


	for (i = 0; i < num; i++) {

		valid = 0;
		memset(&tmp, 0, sizeof(tmp));
		tmp.valid_byte = compute_valid_num((unsigned char *)arr[i], info->object_size);

		if (tmp.valid_byte < 4)
			continue;

		tmp.ptr = (void *)arr[i];

		for (j = 0; j < num; j++) {

			if (i == j)
				continue;

			ret = compare_one_object(&tmp, (unsigned char *)(arr[j]), info->object_size);
			if (ret)
				valid++;
		}

		if (valid > max) {
			max = valid;
			*object = tmp;
			object->valid_object = max;
		}

		if ((object->valid_object * 2) >= num)
			break;
	}

	return 0;
}

static int merge_similar_object(struct object_info *info, struct object *object, int i)
{
	int merge = 0;
	struct object *tmp;
	unsigned char *ptr = (unsigned char *)object->ptr;

	if (object->valid_object < i / 2) {
		return 1;
	}

	list_for_each_entry(tmp, &info->head, node) {

		merge = compare_one_object(tmp, ptr, info->size);
		if (merge)
			break;
	}

	if (!info->object)
		info->object = object;

	if (merge) {
		//printk("merge similar object byte %d src %p dst %p\n", object->valid_byte, tmp->ptr, object->ptr);
		tmp->valid_object += object->valid_object;

		if (tmp->valid_object > info->object->valid_object)
			info->object = tmp;

	} else {
		info->num++;
		list_add(&object->node, &info->head);
	}

	return merge;
}

static int scan_one_page(struct page *page, struct object_info *info)
{
	void *p;
	int n;
	int num = PAGE_SIZE / info->size;
	char unuse[num];
	int i = num;
	struct object *object;
	void *meta;
	unsigned long long *tmp;

	void *start = page_address(page);
	void *end = start + PAGE_SIZE;

	memset(unuse, 0, sizeof(unuse));

	for (p = page->freelist; p && p < end; p = (*(void **)p)) {
		n = (p - start) / info->size ;
		if (n < num) {
			unuse[n] = 1;
			i--;
		}
	}

	if ( i <= (num >> 1))
		return 0;

	object = internal_alloc(sizeof(*object), GFP_KERNEL);
	if (!object) {
		printk(" alloc object info error\n");
		return 0;
	}

	memset(object, 0, sizeof(*object));

	meta = internal_alloc(sizeof(void *) * i, GFP_KERNEL);
	if (!meta) {
		internal_kfree(object);
		return 0;
	}

	memset(meta, 0, sizeof(void *) * i);

	tmp = (unsigned long long *)meta;

	for (n = 0; n < num; n++) {
		if (unuse[n])
			continue;
		*tmp = (unsigned long long )(start + n * info->size);
		tmp++;
	}


	find_similar_object(info, object, (unsigned long long *)meta, i);

	object->page = (void *)start;

	n = merge_similar_object(info, object, i);
	if (n) {
		internal_kfree(object);
	}

	internal_kfree(meta);

	return 0;
}

int memleak_free_object(struct memleak_htab *htab)
{
	struct object *tmp1, *tmp2;
	struct object_info *info = &htab->info;

	if (!htab->check.cache)
		return 0;

	list_for_each_entry_safe(tmp1, tmp2, &info->head, node) {
		list_del_init(&tmp1->node);
		internal_kfree(tmp1);
	}

	memset(info, 0, sizeof(*info));
	INIT_LIST_HEAD(&info->head);

	return 0;
}

int  memleak_max_object(struct memleak_htab *htab)
{
	int i = 0;
	struct object_info *info = &htab->info;
	struct kmem_cache *cache = htab->check.cache;
	struct object *object;

	memset(info, 0, sizeof(*info));
	INIT_LIST_HEAD(&info->head);

	if (!cache) {
		printk("slab cache is null\n");
		return 0;
	}

	if (htab->rate)
		rate = htab->rate;

	info->object_size = cache->object_size;
	info->size = cache->size;

	for_each_online_node(i) {
		unsigned long start_pfn = node_start_pfn(i);
		unsigned long end_pfn = node_end_pfn(i);
		unsigned long pfn;
		unsigned long order;

		for (pfn = start_pfn; pfn < end_pfn;) {
			struct page *page = NULL;

			cond_resched();

			if (!pfn_valid(pfn)) {
				pfn++;
				continue;
			}

			page = pfn_to_page(pfn);
			if (!page) {
				pfn++;
				continue;
			}

			if (PageCompound(page))
				order = compound_order(page);
			else if (PageBuddy(page))
				order = page->private;
			else
				order = 0;
			pfn += (1 << (order >= MAX_ORDER ? 0 : order));

			/* only scan pages belonging to this node */
			if (page_to_nid(page) != i)
				continue;
			/* only scan if page is in use */
			if (page_count(page) == 0)
				continue;
			/*only scan slab page */
			if (!PageSlab(page))
				continue;
			/*only scan target slab */
			if (page->slab_cache != cache)
				continue;

			scan_one_page(page, info);
		}
	}

	printk("find object %d\n", info->num);
	object = info->object;
	if (object)
		printk("start %p ptr %p byte %d object %d \n", object->page, object->ptr, object->valid_byte, object->valid_object);

	return 0;
}

int memleak_mark_leak(struct memleak_htab *htab, struct alloc_desc *desc)
{
	struct object_info *info = &htab->info;

	if (!htab->check.cache || !info->object || !desc)
		return 0;

	return !!compare_one_object(info->object, (unsigned char *)desc->ptr, info->object_size);
}

