#ifndef __CGTRACE_COMM_H
#define __CGTRACE_COMM_H

typedef u32 uint32_t;
typedef u64 uint64_t;
typedef u16 uint16_t;
typedef u8 uint8_t;

struct mm_struct___MEMCG {
	struct {
		struct vm_area_struct *mmap;
		struct rb_root mm_rb;
		u64 vmacache_seqnum;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		long unsigned int highest_vm_end;
		pgd_t *pgd;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_sem;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		long unsigned int pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[46];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		struct core_state *core_state;
		atomic_t membarrier_state;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		struct mmu_notifier_mm *mmu_notifier_mm;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		bool tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
	};
	long unsigned int ali_reserved1;
	long unsigned int ali_reserved2;
	long unsigned int cpu_bitmap[0];
};

struct page_counter {
	atomic_long_t usage;
	long unsigned int min;
	long unsigned int low;
	long unsigned int max;
	struct page_counter *parent;
	long unsigned int emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;
	long unsigned int elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;
	long unsigned int wmark_low;
	long unsigned int wmark_high;
	long unsigned int watermark;
	long unsigned int failcnt;
};

struct vmpressure {
	long unsigned int scanned;
	long unsigned int reclaimed;
	long unsigned int tree_scanned;
	long unsigned int tree_reclaimed;
	struct spinlock sr_lock;
	struct list_head events;
	struct mutex events_lock;
	struct work_struct work;
};

struct mem_cgroup_thresholds {
	struct mem_cgroup_threshold_ary *primary;
	struct mem_cgroup_threshold_ary *spare;
};

struct memcg_padding {
	char x[0];
};

enum memcg_kmem_state {
	KMEM_NONE = 0,
	KMEM_ALLOCATED = 1,
	KMEM_ONLINE = 2,
};

struct mem_cgroup_id {
	int id;
	atomic_t ref;
};

struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	long unsigned int split_queue_len;
};

union kernfs_node_id {
	struct {
		u32 ino;
		u32 generation;
	};
	u64 id;
};

struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	struct page_counter memory;
	struct page_counter swap;
	struct page_counter memsw;
	struct page_counter kmem;
	struct page_counter tcpmem;
	long unsigned int high;
	struct work_struct high_work;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool use_hierarchy;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct memcg_padding _pad1_;
	atomic_t moving_account;
	struct task_struct *move_lock_task;
	struct mem_cgroup_stat_cpu *stat_cpu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct memcg_padding _pad2_;
	atomic_long_t stat[35];
	atomic_long_t events[84];
	atomic_long_t memory_events[7];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	unsigned int wmark_ratio;
	struct work_struct wmark_work;
	unsigned int wmark_scale_factor;
	int kmemcg_id;
	enum memcg_kmem_state kmem_state;
	struct list_head kmem_caches;
	int last_scanned_node;
	nodemask_t scan_nodes;
	atomic_t numainfo_events;
	atomic_t numainfo_updating;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	long unsigned int ali_reserved1;
	long unsigned int ali_reserved2;
	long unsigned int ali_reserved3;
	long unsigned int ali_reserved4;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cgroup___MEMCG {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int id;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat pending_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	int ancestor_ids[0];
};

struct kernfs_node___419 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	void *priv;
	union kernfs_node_id id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct cpuacct___AVE {
	struct cgroup_subsys_state css;
	struct cpuacct_usage *cpuusage;
	struct cpuacct_alistats *alistats;
	struct kernel_cpustat *cpustat;
	long unsigned int avenrun[3];
	long unsigned int avenrun_r[3];
	struct list_head sli_list;
	bool sli_enabled;
	struct sched_cgroup_lat_stat_cpu *lat_stat_cpu;
	u64 next_load_update;
	long unsigned int ali_reserved1;
	long unsigned int ali_reserved2;
	long unsigned int ali_reserved3;
	long unsigned int ali_reserved4;
};

#endif
