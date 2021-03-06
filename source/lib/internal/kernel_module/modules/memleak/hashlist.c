#include<linux/gfp.h>
#include"mem.h"

static DEFINE_PER_CPU(int, nest_count);

static inline u32 ptr_hash(const void *ptr)
{
    return jhash((void *)&ptr, sizeof(ptr), 0);
}

static inline struct bucket *__select_bucket(struct memleak_htab *htab, u32 hash)
{
    return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static inline struct list_head *select_bucket(struct memleak_htab *htab, u32 hash)
{
    return &__select_bucket(htab, hash)->head;
}

 void *internal_alloc(size_t size, gfp_t flags)
{
    void *ret;

    per_cpu(nest_count, smp_processor_id()) += 1;
    ret = kmalloc(size, flags);
    per_cpu(nest_count, smp_processor_id()) -= 1;

    return ret;
}

 void internal_kfree(void *addr)
{
    per_cpu(nest_count, smp_processor_id()) += 1;
    kfree(addr);
    per_cpu(nest_count, smp_processor_id()) -= 1;
}

int memleak_entry_reentrant(void)
{
 	per_cpu(nest_count, smp_processor_id()) += 1;
	return per_cpu(nest_count, smp_processor_id()) > 1;
}

void memleak_exit_reentrant(void)
{
	per_cpu(nest_count, smp_processor_id()) -= 1;
}

int  memleak_hashlist_init(struct memleak_htab *htab)
{
	int i = 0;
	int size;
	struct alloc_desc *desc;

	htab->buckets = internal_alloc(htab->n_buckets * sizeof(struct bucket), GFP_KERNEL);
	if (!htab->buckets) {
		return -ENOMEM;
	}

	memset(htab->buckets, 0, htab->n_buckets * sizeof(struct bucket));

	INIT_LIST_HEAD(&htab->freelist);

	for (i = 0; i < htab->n_buckets; i++) {
		INIT_LIST_HEAD(&htab->buckets[i].head);
		spin_lock_init(&htab->buckets[i].lock);

	}

	htab->free = 0;

	size = sizeof(struct alloc_desc) + sizeof(u64) * htab->stack_deep;
	/*prealloc one by one */
	for (i = 0; i < htab->total; i++) {
		desc = internal_alloc(size, GFP_KERNEL | __GFP_ZERO);
		if (desc) {
			desc->num = htab->stack_deep;
			list_add(&desc->node, &htab->freelist);
			htab->free++;
		}
	}

	return 0;
}

struct alloc_desc *  memleak_alloc_desc(struct memleak_htab *htab)
{
	struct alloc_desc *desc;
	unsigned long flags;
	int size = sizeof(struct alloc_desc) + sizeof(u64) * htab->stack_deep;

	if (!htab->set.ext)
		htab->stack_deep = 0;

	if (!htab->free) {
		desc = internal_alloc(size, GFP_ATOMIC | __GFP_ZERO);
		if (desc)
			desc->num = htab->stack_deep;
		return desc;
	}
	spin_lock_irqsave(&htab->lock, flags);

	desc = list_first_entry_or_null(&htab->freelist, struct alloc_desc, node);
	if (desc) {
		htab->free--;
		desc->num = htab->stack_deep;
		list_del_init(&desc->node);
	}

	spin_unlock_irqrestore(&htab->lock, flags);

	return desc;
}

int memleak_free_desc(struct memleak_htab *htab, struct alloc_desc *desc)
{
	unsigned long flags;

	if (!desc)
		return 0;

	if (htab->free >= htab->total) {

		internal_kfree(desc);
		return 0;
	}

	spin_lock_irqsave(&htab->lock, flags);

	memset(desc, 0, sizeof(*desc));
	list_add(&desc->node, &htab->freelist);
	htab->free++;

	spin_unlock_irqrestore(&htab->lock, flags);

	return 0;
}

int memleak_insert_desc(struct memleak_htab *htab, struct alloc_desc *desc)
{
	unsigned long flags;
	struct bucket *bucket;

	if (!desc || !desc->ptr)
		return 0;

	desc->hash = ptr_hash(desc->ptr);

	bucket	= __select_bucket(htab, desc->hash);

	spin_lock_irqsave(&bucket->lock, flags);

	list_add(&desc->node, &bucket->head);
	bucket->nr++;
	atomic_add(1, &htab->count);
	spin_unlock_irqrestore(&bucket->lock,flags);

	return 0;
}

struct alloc_desc *  memleak_del_desc(struct memleak_htab *htab, const void *ptr)
{
	unsigned long flags;
	struct bucket *bucket;
	struct alloc_desc *tmp1, *tmp2;
	struct alloc_desc *desc = NULL;
	u32 hash;

	if (!ptr)
		return NULL;

	hash = ptr_hash(ptr);
	bucket = __select_bucket(htab, hash);

	spin_lock_irqsave(&bucket->lock, flags);

	list_for_each_entry_safe(tmp1, tmp2, &bucket->head, node) {
		if (tmp1->ptr == ptr && (tmp1->hash == hash)) {
			list_del_init(&tmp1->node);
			desc = tmp1;
			bucket->nr--;
			atomic_sub(1, &htab->count);
			break;
		}
	}

	spin_unlock_irqrestore(&bucket->lock, flags);


	return desc;
}

int memleak_hashlist_uninit(struct memleak_htab *htab)
{
	struct bucket *bucket;
	struct alloc_desc *tmp1, *tmp2;
	int i;

	htab->free = 0;

	for (i = 0; i < htab->n_buckets; i++) {
		bucket = &htab->buckets[i];

		list_for_each_entry_safe(tmp1, tmp2, &bucket->head, node) {
			list_del_init(&tmp1->node);
			internal_kfree(tmp1);
			htab->free++;
		}
	}

	list_for_each_entry_safe(tmp1, tmp2, &htab->freelist, node) {
		list_del_init(&tmp1->node);
		internal_kfree(tmp1);
		htab->free++;
	}

	if (htab->free != htab->total)
		pr_info("memleak free %u ,total %u\n", htab->free, htab->total);

	if (htab->buckets)
		internal_kfree(htab->buckets);

	htab->buckets = NULL;

	return 0;
}

static void memleak_dump_object(struct memleak_htab *htab, struct max_object *object)
{
	struct kmem_cache *cache = htab->check.cache;

	if (!cache || !object)
		return ;

	strncpy(object->slabname, cache->name, NAME_LEN);
	object->object_size = cache->size;
	object->object_num = htab->check.object_num;

	if (!htab->info.object)
		return ;

	object->similar_object = htab->info.object->valid_object;
	object->ptr = htab->info.object->ptr;
}


int memleak_dump_leak(struct memleak_htab *htab, struct user_result __user *result)
{
	struct bucket *bucket;
	struct alloc_desc *tmp1, *tmp2;
	struct user_alloc_desc *desc;
	struct user_result res;
	struct max_object object;
	void __user *tmp;

	int i = 0;
	int j = 0;
	int num = 0;
	int count = atomic_read(&htab->count);
	int ret = 0;
	unsigned long long curr_ts = sched_clock();

	if ((count <= 0) || copy_from_user(&res, result, sizeof(res))) {
		pr_err("count zero %d:%d\n",count,__LINE__);
		ret = copy_to_user(result, &i, sizeof(i));
		return 0;
	}

	if (!res.num || !res.desc) {
		pr_err("num %d ,desc %p \n", res.num, res.desc);
		ret = copy_to_user(result, &i, sizeof(i));
		return 0;
	}

	pr_info("total memleak number %d user %d ts=%llu\n", count, res.num, sched_clock());

	res.num = (res.num > count) ? count : res.num;
	num = res.num;

	desc = vmalloc(sizeof(*desc) * num);
	if (!desc) {
		pr_err("vmalloc error %d:%d\n",count,__LINE__);
		ret = copy_to_user(result, &i, sizeof(i));
		return 0;
	}

	tmp = res.desc;
	res.desc = desc;
	j = 0;

	/*copy object info */
	if (res.objects) {
		memset(&object, 0, sizeof(object));
		memleak_dump_object(htab, &object);
		ret = copy_to_user(res.objects, &object, sizeof(object));
	}

	for (i = 0; i < htab->n_buckets; i++) {
		int z = 0;
		bucket = &htab->buckets[i];
		if (bucket->nr <= 0) {
			continue;
		}

		list_for_each_entry_safe(tmp1, tmp2, &bucket->head, node) {
			list_del_init(&tmp1->node);
			if ((htab->set.type == MEMLEAK_TYPE_PAGE) && PageSlab((struct page*)tmp1->ptr)) {
				goto _skip;
			}

			desc->ts = (curr_ts - tmp1->ts)>>30;
			desc->ptr = tmp1->ptr;
			desc->pid = tmp1->pid;
			desc->mark = memleak_mark_leak(htab, tmp1);
			desc->order = tmp1->order;
			desc->call_site = tmp1->call_site;
			strcpy(desc->comm,tmp1->comm);
			snprintf(desc->function, NAME_LEN, "%pS", (void *)tmp1->call_site);
			desc->num = tmp1->num;
			for (z = 0; z < desc->num; z++) {
				snprintf(desc->backtrace[z], 128, "%pS", tmp1->backtrace[z]);
			}
			desc++;
			j++;
_skip:
			memleak_free_desc(htab, tmp1);
			atomic_sub(1, &htab->count);
			bucket->nr--;
			if (!--num)
				goto _out;
			}
	}

_out:

	i = copy_to_user(result, &j, sizeof(j));
	i = copy_to_user(tmp, res.desc, sizeof(*desc) * j);

	vfree(res.desc);
	pr_info("get num %d htab %d, %d\n", j, atomic_read(&htab->count), num);
	return i;
}

int memleak_clear_leak(struct memleak_htab *htab)
{
	struct bucket *bucket;
	struct alloc_desc *tmp1, *tmp2;
	int i;


	if (!atomic_read(&htab->count)) {
		return 0;
	}

	pr_info(" clear leak %d \n", atomic_read(&htab->count));


	for (i = 0; i < htab->n_buckets; i++) {

		bucket = &htab->buckets[i];
		cond_resched();

		if (bucket->nr) {

			list_for_each_entry_safe(tmp1, tmp2, &bucket->head, node) {

				list_del_init(&tmp1->node);
				memleak_free_desc(htab, tmp1);
			}
		}

		bucket->nr = 0;
	}

	atomic_set(&htab->count, 0);

	return 0;
}
