#include<linux/module.h>
#include<linux/printk.h>
#include<linux/kallsyms.h>
#include<linux/version.h>
#include <linux/mmzone.h>
#include <linux/page-flags.h>

#include"mem.h"
#include"common/hook.h"

#define HASH_SIZE (2048)
#define PRE_ALLOC (2048)

static struct memleak_htab *tab;
static ssize_t (*show_slab_objects)(struct kmem_cache *s, char *buf);

static int memleak_is_target(struct memleak_htab *htab, const void *x)
{
	struct page *page;


	if (!htab->check.cache)
		return 1;

	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return 0;

	page = virt_to_head_page(x);
	if (!page || unlikely(!PageSlab(page))) {
		return 0;
	}

	return (page->slab_cache == htab->check.cache);
}


static void memleak_alloc_desc_push(struct memleak_htab *htab, unsigned long call_site, const void *ptr, int order)
{
	unsigned long flags;
	struct alloc_desc *desc;

	if (!ptr || !memleak_is_target(htab, ptr))
		return;

	local_irq_save(flags);
	if (memleak_entry_reentrant())
		goto _out;

	desc = memleak_alloc_desc(htab);
	if (!desc)
		goto _out;

	desc->call_site = call_site;
	desc->ptr = ptr;
	desc->order = order;
	desc->ts = sched_clock();
	desc->pid = current->pid;
	strcpy(desc->comm, current->comm);

	memleak_insert_desc(htab, desc);

_out:
	memleak_exit_reentrant();
	local_irq_restore(flags);
}

static void memleak_alloc_desc_pop(struct memleak_htab *htab,unsigned long call_site, const void *ptr,int order)
{
	unsigned long flags;
	struct alloc_desc *desc;

	if (!ptr || !memleak_is_target(htab, ptr))
		return;

	local_irq_save(flags);

	if (memleak_entry_reentrant())
		goto _out;

	desc = memleak_del_desc(htab, ptr);
	memleak_free_desc(htab, desc);

_out:
	memleak_exit_reentrant();
	local_irq_restore(flags);
}

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_slab_alloc(void *__data, unsigned long call_site, const void *ptr,
         size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
#else
static void trace_slab_alloc(unsigned long call_site, const void *ptr,
         size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
#endif
{
	memleak_alloc_desc_push(tab, call_site, ptr, 0);
}

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_slab_free(void *ignore, unsigned long call_site, const void *ptr)
#else
static void trace_slab_free(unsigned long call_site, const void *ptr)
#endif
{

	memleak_alloc_desc_pop(tab, call_site, ptr, 0);
}

#ifdef CONFIG_NUMA
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_slab_alloc_node(void *__data, unsigned long call_site, const void *ptr,
         size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node)
#else
static void trace_slab_alloc_node(unsigned long call_site, const void *ptr,
         size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node)
#endif
{
	memleak_alloc_desc_push(tab, call_site, ptr, 0);
}

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void trace_page_alloc(void *ignore, struct page *page,
        unsigned int order, gfp_t gfp_flags, int migratetype)
#else
static void trace_page_alloc(struct page *page,
        unsigned int order, gfp_t gfp_flags, int migratetype)
#endif
{

	if ((migratetype == 1) || (migratetype == 2)) {
		return;
	}

	memleak_alloc_desc_push(tab, (unsigned long )__builtin_return_address(3), page, order);

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void trace_page_free(void *ignore, struct page *page,
        unsigned int order)
#else
static void trace_page_free(struct page *page,
        unsigned int order)
#endif
{
	if (((unsigned long)page->mapping & PAGE_MAPPING_FLAGS) != 0)
		return;

	memleak_alloc_desc_pop(tab, (unsigned long)__builtin_return_address(3), page, order);
}



static int slab_tracepoint_init(void)
{
	int ret = 0;

	ret = hook_tracepoint("kmem_cache_alloc", trace_slab_alloc, NULL);
	if (ret) {
		pr_err("memleak register kmem cache alloc tracepoint error %d\n", ret);
	}

	ret = hook_tracepoint("kmem_cache_free", trace_slab_free, NULL);
	if (ret) {
		pr_err("memleak register kmem cache free tracepoint error %d\n", ret);
	}

	ret = hook_tracepoint("kmalloc", trace_slab_alloc, NULL);
	if (ret) {
		pr_err("memleak register kmalloc tracepoint error %d\n", ret);
	}

	ret = hook_tracepoint("kfree", trace_slab_free, NULL);
	if (ret) {
		pr_err("memleak register kfree tracepoint error %d\n", ret);
	}

#ifdef CONFIG_NUMA
	ret = hook_tracepoint("kmalloc_node", trace_slab_alloc_node, NULL);
	if (ret) {
		pr_err("memleak register kmalloc node  tracepoint error %d\n", ret);
	}
#ifdef CONFIG_NUMA
	ret = hook_tracepoint("kmem_cache_alloc_node", trace_slab_alloc_node, NULL);
	if (ret) {
		pr_err("memleak register kmem_cache_alloc  node  tracepoint error %d\n", ret);
	}
#endif
#endif
	return 0;
}

static void slab_tracepoint_alloc_uninit(void)
{
	unhook_tracepoint("kmem_cache_alloc", trace_slab_alloc, NULL);
	unhook_tracepoint("kmalloc", trace_slab_alloc, NULL);

#ifdef CONFIG_NUMA
	unhook_tracepoint("kmalloc_node", trace_slab_alloc_node, NULL);
#ifdef CONFIG_TRACING
	unhook_tracepoint("kmem_cache_alloc_node", trace_slab_alloc_node, NULL);
#endif
#endif
}

static void slab_tracepoint_free_uninit(void)
{
	unhook_tracepoint("kfree", trace_slab_free, NULL);
	unhook_tracepoint("kmem_cache_free", trace_slab_free, NULL);
}

static void page_tracepoint_init(void)
{
	int ret = 0;

	ret = hook_tracepoint("mm_page_free", trace_page_free, NULL);
	if(ret)
		pr_err("register mm page free error\n");


	ret = hook_tracepoint("mm_page_alloc", trace_page_alloc, NULL);
	if(ret)
		pr_err("register mm page alloc error\n");
}

static void page_tracepoint_alloc_uninit(void)
{

	unhook_tracepoint("mm_page_alloc", trace_page_alloc, NULL);
}

static void page_tracepoint_free_uninit(void)
{

	unhook_tracepoint("mm_page_free", trace_page_free, NULL);
}

static void memleak_tracepoint_init(struct memleak_htab *htab)
{
	if (htab->set.type == MEMLEAK_TYPE_SLAB) {
		slab_tracepoint_init();
	}else if (htab->set.type == MEMLEAK_TYPE_PAGE) {
		page_tracepoint_init();
	} else
		pr_err("trace type error %d\n", htab->set.type);
}

static void memleak_tracepoint_alloc_uninit(struct memleak_htab *htab)
{
	if (htab->set.type == MEMLEAK_TYPE_SLAB) {
		slab_tracepoint_alloc_uninit();
	} else if (htab->set.type == MEMLEAK_TYPE_PAGE) {
		page_tracepoint_alloc_uninit();
	} else
		pr_err("trace alloc uninit type %d\n", htab->set.type);
}

static void memleak_tracepoint_free_uninit(struct memleak_htab *htab)
{
	if (htab->set.type == MEMLEAK_TYPE_SLAB) {
		slab_tracepoint_free_uninit();
	} else if (htab->set.type == MEMLEAK_TYPE_PAGE) {
		page_tracepoint_free_uninit();
	} else
		pr_err("trace free uninit type %d\n", htab->set.type);

}

static unsigned long  str2num(char *buf)
{
	unsigned long objects = 0;
	int ret;
	char * tmp = buf;

	while (*buf && *++buf != ' ');

	if (!*buf)
		return 0;

	*buf = 0;
	ret = kstrtoul(tmp, 10, &objects);
	return objects;
}

static int memleak_get_maxslab(struct memleak_htab *htab)
{
	unsigned long size = 0;
	unsigned long max = 0;
	struct kmem_cache *tmp;
	char object_buffer[NAME_LEN];
	void **show_slab = (void **)&show_slab_objects;

#ifndef CONFIG_SLUB_DEBUG
	return 0;
#endif

	*show_slab = (void *)kallsyms_lookup_name("objects_show");
	if (!*show_slab) {
		pr_err("Get show_slab objects error\n");
		return 0;
	}

	mutex_lock(htab->check.slab_mutex);

	list_for_each_entry(tmp, htab->check.slab_caches, list) {
		if (tmp->flags & SLAB_RECLAIM_ACCOUNT)
			continue;

		size = show_slab_objects(tmp, object_buffer);
		if (size < 0)
			continue;

		size = str2num(object_buffer);
		if (size <= 0)
			continue;

		if (size > max) {
			max = size;
			htab->check.cache = tmp;
			htab->check.object_num = max;
		}
	}

	if (htab->check.cache)
		pr_info("max cache %s size = %lu \n", htab->check.cache->name, max);

	mutex_unlock(htab->check.slab_mutex);

	return 0;
}

static int memleak_slab_init(struct memleak_htab *htab)
{
	struct mutex *slab_mutex;
	struct kmem_cache *s;
	struct list_head *slab_caches;

	slab_mutex = (struct mutex *)kallsyms_lookup_name("slab_mutex");
	slab_caches = (struct list_head *)kallsyms_lookup_name("slab_caches");

	if (!slab_mutex || !slab_caches) {
		pr_err("memleak:can't get slab mutex/caches %p:%p\n", slab_mutex, slab_caches);
		return -EIO;
	}

	htab->check.slab_mutex = slab_mutex;
	htab->check.slab_caches = slab_caches;
	htab->check.object_num = 0;

	if (!htab->set.name[0]) {
		memleak_get_maxslab(htab);
		goto _out;
	}

	if (!strcmp(htab->set.name, "all"))
		return 0;

	mutex_lock(slab_mutex);

	list_for_each_entry(s, slab_caches, list) {
		if (!strcmp(s->name, htab->set.name)) {
			htab->check.cache = s;
			pr_info("get slab %s,%p\n",s->name, htab->check.cache);
			break;
		}
	}

	mutex_unlock(slab_mutex);

_out:
	return !htab->check.cache;
}


static int memleak_mem_init(struct memleak_htab *htab)
{

	htab->n_buckets = HASH_SIZE;
	htab->total = PRE_ALLOC;
	htab->stack_deep = 0;

	return memleak_hashlist_init(tab);
}

static void  memleak_mem_uninit(struct memleak_htab *htab)
{
	memleak_hashlist_uninit(htab);
}

static void memleak_delay_work(struct work_struct *work)
{
	struct memleak_htab *htab;
	int delay = 0;

	htab = (struct memleak_htab *)container_of(work, struct memleak_htab, work.work);

	if (htab->state == MEMLEAK_STATE_INIT) {
		pr_err("memleak delay work state on\n");
		memleak_tracepoint_alloc_uninit(htab);

		htab->state = MEMLEAK_STATE_ON;
		delay = (htab->set.monitor_time * htab->set.rate)/100;
		schedule_delayed_work(&htab->work, HZ * delay);

	} else if (htab->state == MEMLEAK_STATE_ON) {

		pr_err("memleak delay work state off\n");

		memleak_tracepoint_free_uninit(htab);

		htab->state = MEMLEAK_STATE_OFF;
	}
}

static int memleak_trace_slab(struct memleak_htab *htab)
{
	int ret;

	htab->check.cache = NULL;
	htab->check.object_num = 0;
	atomic_set(&htab->count, 0);

	ret = memleak_slab_init(htab);

	memleak_max_object(htab);

	return ret;
}

static int memleak_trace_slab_uninit(struct memleak_htab *htab)
{
	if (htab->set.type != MEMLEAK_TYPE_SLAB)
		return 0;

	memleak_free_object(htab);

	htab->check.cache = NULL;
    htab->check.object_num = 0;

	return 0;
}

int memleak_trace_off(struct memleak_htab *htab)
{
	cancel_delayed_work_sync(&htab->work);

	if (htab->state == MEMLEAK_STATE_INIT) {

		memleak_tracepoint_alloc_uninit(htab);
		memleak_tracepoint_free_uninit(htab);

	} else if (htab->state == MEMLEAK_STATE_ON) {
		memleak_tracepoint_free_uninit(htab);
	}

	htab->state = MEMLEAK_STATE_OFF;

	memleak_trace_slab_uninit(htab);

	return 0;
}

 int memleak_trace_on(struct memleak_htab *htab)
{
	int ret = 0;
	int delay = 0;

	if (!htab)
		return ret;

	if (!htab->set.monitor_time)
		htab->set.monitor_time = MONITOR_TIME;

	if (!htab->set.rate)
		htab->set.rate = MONITOR_RATE;

	if (!htab->set.type)
		htab->set.type = MEMLEAK_TYPE_SLAB;

	switch (htab->set.type) {

	case MEMLEAK_TYPE_VMALLOC:
		pr_info("trace vmalloc\n");
		break;
	case MEMLEAK_TYPE_PAGE:
		pr_info("trace alloc page\n");
		break;
	default:
		ret = memleak_trace_slab(htab);
	}

	htab->state = MEMLEAK_STATE_INIT;
	atomic_set(&htab->count, 0);

	memleak_tracepoint_init(htab);

	atomic_set(&htab->count, 0);
	delay = htab->set.monitor_time;
	delay = delay - (delay * htab->set.rate)/100;

	pr_info("delay = %d\n",delay);
	schedule_delayed_work(&htab->work, HZ * delay);

	return ret;
}

static int memleak_release(struct memleak_htab *htab)
{

	memleak_trace_off(htab);
    memleak_clear_leak(htab);

	return 0;
}

int memleak_handler_cmd(int cmd, unsigned long arg)
{
    int ret = -EINVAL;
    struct memleak_settings set;
	struct memleak_htab * htab = tab;

    if (!htab || htab->state != MEMLEAK_STATE_OFF) {
       	pr_info("htab is busy\n");
		return -EBUSY;
	}

    switch (cmd) {

        case MEMLEAK_CMD_ENALBE:
            ret = copy_from_user(&set, (void *)arg, sizeof(set));
            if (ret)
                return ret;
            pr_info("type = %d time = %d,slabname %s ext %d,rate=%d\n",set.type, set.monitor_time, set.name, set.ext,set.rate);
            htab->set = set;
            ret = memleak_trace_on(htab);

            break;

        case MEMLEAK_CMD_RESULT:
            pr_info("get result\n");
            ret = memleak_dump_leak(htab, (struct user_result __user*)arg);
            break;

		case MEMLEAK_CMD_DISABLE:
			pr_info("disable\n");
			memleak_release(htab);

    };

    return ret;
}

 int  memleak_init(void)
{
	int ret = 0;

	tab = kzalloc(sizeof(struct memleak_htab), GFP_KERNEL);
	if (!tab) {
		pr_err("alloc memleak hash table failed\n");
		return -ENOMEM;
	}

	spin_lock_init(&tab->lock);
	INIT_DELAYED_WORK(&tab->work, memleak_delay_work);
	tab->state = MEMLEAK_STATE_OFF;

	ret = memleak_mem_init(tab);
	if (ret)
		kfree(tab);

	return 0;
}

int memleak_uninit(void)
{
	if (!tab)
		return 0;

	memleak_release(tab);

	memleak_mem_uninit(tab);

	kfree(tab);

	return 0;
}
