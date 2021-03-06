#ifndef __MEMLEAK__
#define __MEMLEAK__
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/kernel.h>
#include <asm/unistd_64.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include "common.h"
#include "memleak.h"
#include "user.h"

struct bucket {
	struct list_head head;
	u32 nr;
	spinlock_t lock;
};

struct slab_info {
	struct mutex *slab_mutex;
	struct list_head *slab_caches;
	struct kmem_cache *cache;
	unsigned long object_num;
};

struct object {
    struct list_head node;
    void *ptr;
    int valid_byte;
    int valid_object;
    void *page;
};

struct object_info {
    struct list_head head;
	struct object *object;
    int object_size;
    int size;
    int num;
};


struct memleak_htab {
	struct bucket *buckets;
	struct list_head freelist;
	spinlock_t lock;
	u32 n_buckets;
	u32 free;
	u32 total;
	u32 stack_deep;
	atomic_t  count;
	int state;
	int rate;
	struct slab_info check;
	struct object_info info;
	struct delayed_work work;
	struct memleak_settings set;
};

struct alloc_desc {
	struct list_head node;
	unsigned long ts;
	const void *ptr;
	unsigned long long call_site;
	int pid;
	int order;
	char comm[TASK_COMM_LEN];
	u32 hash;
	u64 backtrace[];
};

int  memleak_hashlist_init(struct memleak_htab *htab);
struct alloc_desc *  memleak_alloc_desc(struct memleak_htab *htab);
int memleak_free_desc(struct memleak_htab *htab, struct alloc_desc *desc);
int memleak_insert_desc(struct memleak_htab *htab, struct alloc_desc *desc);
struct alloc_desc * memleak_del_desc(struct memleak_htab *htab, const void *ptr);
int memleak_hashlist_uninit(struct memleak_htab *htab);
int memleak_entry_reentrant(void);
void memleak_exit_reentrant(void);
int memleak_dump_leak(struct memleak_htab *htab, struct user_result *result);

void * internal_alloc(size_t size, gfp_t flags);
void internal_kfree(void *addr);


int memleak_clear_leak(struct memleak_htab *htab);
int memleak_trace_off(struct memleak_htab *htab);
int memleak_trace_on(struct memleak_htab *htab);

int memleak_handler_cmd(int cmd, unsigned long arg);
int memleak_mark_leak(struct memleak_htab *htab, struct alloc_desc *desc);
int memleak_free_object(struct memleak_htab *htab);
int  memleak_max_object(struct memleak_htab *htab);
#endif
