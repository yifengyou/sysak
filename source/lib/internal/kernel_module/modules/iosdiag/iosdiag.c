
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include "iosdiag.h"
#include <virtio_blk.h>

#define DISKHANG_DIR_NAME	"disk_hang"

#define DEFINE_PROC_ATTRIBUTE(name, __write, __mmap)			\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode)); \
	}								\
	static const struct file_operations name##_fops = {		\
		.owner		= THIS_MODULE,				\
		.open		= name##_open,				\
		.read		= seq_read,				\
		.write		= __write,				\
		.mmap		= __mmap,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	}

#define DEFINE_PROC_ATTRIBUTE_RW(name)					\
	static ssize_t name##_write(struct file *file,			\
				    const char __user *buf,		\
				    size_t count, loff_t *ppos)		\
	{								\
		return name##_store(PDE_DATA(file_inode(file)), buf,	\
				    count);				\
	}								\
	DEFINE_PROC_ATTRIBUTE(name, name##_write, name##_mmap)

static DEFINE_MUTEX(rq_hang_buffer_mutex);

struct rq_store {
	struct list_head list;
	struct request *rq;
};
static struct rq_store g_rq_store[MAX_STORE_RQ_CNT];
static struct rq_hang_info *g_rq_hang_info;
static int g_rq_hang_idx;
static unsigned long long g_rq_hang_total;
static int g_disk_type = -1;
static int g_bio_file_info;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
fn_queue_tag_busy_iter sym_blk_mq_queue_tag_busy_iter = NULL;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
typedef void (*fn_mq_free_request)(struct request *rq);
static fn_mq_free_request sym_blk_mq_free_request;
#endif
fn_get_files_struct sym_get_files_struct = NULL;
fn_put_files_struct sym_put_files_struct = NULL;

static void set_disk_type(char *buf)
{
	if (buf[0] == 'v' && buf[1] == 'd' && (buf[2] >= 'a' && buf[2] <= 'z'))
		g_disk_type = DISK_VIRTIO_BLK;
	else if (buf[0] == 's' && buf[1] == 'd' && (buf[2] >= 'a' && buf[2] <= 'z'))
		g_disk_type = DISK_SCSI;
	else if (!strncmp(buf, "nvme", 4))
		g_disk_type = DISK_NVME;
	else
		g_disk_type = -1;
}

static int get_disk_type(void)
{
	return g_disk_type;
}

int get_bio_file_info(void)
{
	return g_bio_file_info;
}

static void store_hang_rq(struct request *rq, unsigned long long now)
{
	int index;

	if (g_rq_hang_idx >= MAX_STORE_RQ_CNT)
		return;

	g_rq_hang_total++;
	index = g_rq_hang_idx;
	if (fill_hang_info_from_rq(&g_rq_hang_info[index], rq,
				      get_disk_type()))
		return;
	g_rq_hang_info[index].check_hang_ns = now;
	g_rq_hang_info[index].req_addr = (unsigned long)rq;
	g_rq_hang_idx++;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
static int is_flush_rq(struct request *rq)
{
	struct blk_mq_hw_ctx *hctx = blk_mq_get_hctx_byrq(rq);

	if (hctx && hctx->fq)
		return hctx->fq->flush_rq == rq;
	return 0;
}
#endif

static void mq_check_rq_hang(struct request *rq, void *priv, bool reserved)
{
	int rq_hang_threshold = *((int *)priv);
	u64 now = get_check_hang_time_ns();
	u64 duration;

	if (!rq)
		return;

	if (g_rq_hang_idx >= MAX_STORE_RQ_CNT)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	//if (is_flush_rq(rq) && !enable_detect_flush_rq())
	if (is_flush_rq(rq))
		return;
	if (!refcount_inc_not_zero(&rq->ref))
		return;
#else
	if (!test_bit(REQ_ATOM_STARTED, &rq->atomic_flags))
		return;
#endif
	duration = div_u64(now - rq->start_time_ns, NSEC_PER_MSEC);
	if (duration >= rq_hang_threshold)
		store_hang_rq(rq, now);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	//if (is_flush_rq(rq) && rq->end_io)
	//	rq->end_io(rq, 0);
	//else if (refcount_dec_and_test(&rq->ref))
	if (refcount_dec_and_test(&rq->ref))
		sym_blk_mq_free_request(rq);
#endif
}

static int sq_check_rq_hang(struct request_queue *q, int rq_hang_threshold)
{
	u64 now = get_check_hang_time_ns();
	u64 duration;
	unsigned long flags;
	struct request *rq, *tmp;
	LIST_HEAD(rq_list);
	int rq_store_idx = 0;

 	spin_lock_irqsave(q->queue_lock, flags);
 	list_for_each_entry_safe(rq, tmp, &q->queue_head, queuelist) {
		duration = div_u64(now - rq->start_time_ns, NSEC_PER_MSEC);
 		if (duration >= rq_hang_threshold && rq_store_idx < MAX_STORE_RQ_CNT) {
			 g_rq_store[rq_store_idx].rq = rq;
			 INIT_LIST_HEAD(&g_rq_store[rq_store_idx].list);
			 list_add(&g_rq_store[rq_store_idx].list, &rq_list);
			 rq_store_idx++;
		} else
 			continue;
 	}
	spin_unlock_irqrestore(q->queue_lock, flags);	

 	spin_lock_irqsave(q->queue_lock, flags);
 	list_for_each_entry_safe(rq, tmp, &q->timeout_list, timeout_list) {
		duration = div_u64(now - rq->start_time_ns, NSEC_PER_MSEC);
 		if (duration >= rq_hang_threshold && rq_store_idx < MAX_STORE_RQ_CNT) {
			 g_rq_store[rq_store_idx].rq = rq;
			 INIT_LIST_HEAD(&g_rq_store[rq_store_idx].list);
			 list_add(&g_rq_store[rq_store_idx].list, &rq_list);
			 rq_store_idx++;
		} else
 			continue;
 	}
	spin_unlock_irqrestore(q->queue_lock, flags);
	while(!list_empty(&rq_list)) {
		struct rq_store *rqs;
		rqs = list_first_entry(&rq_list, struct rq_store, list);
		if (rqs->rq)
			store_hang_rq(rqs->rq, now);
		list_del_init(&rqs->list);
	}
	return 0;
}

static int rq_hang_detect(dev_t devnum, int rq_hang_threshold)
{
	int ret = 0;
	struct request_queue *q;
	struct block_device *bdev;

	if (!devnum || rq_hang_threshold <= 0)
		return -EINVAL;

	if (!(bdev = bdget(devnum))) {
		printk("error: invalid devnum(%d:%d)\n", MAJOR(devnum), MINOR(devnum));
		return -EFAULT;
	}
	if (!bdev->bd_queue) {
		if (!bdev->bd_disk || !(q = bdev_get_queue(bdev))) {
			printk("error: can't get request queue for devnum(%d:%d)\n",
				MAJOR(devnum), MINOR(devnum));
				bdput(bdev);
				return -EFAULT;
		}
	} else
		q = bdev->bd_queue;

	if (q->mq_ops)
		ret = iter_all_rq(q, mq_check_rq_hang, &rq_hang_threshold);
	else
		ret = sq_check_rq_hang(q, rq_hang_threshold);
	bdput(bdev);
	return ret;
}

static int rq_hang_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "total_rq_hang:%llu\n", g_rq_hang_total);
	return 0;
}

static ssize_t rq_hang_store(struct file *file,
		const char __user *buf, size_t count)
{
	int ret;
	char *p;
	char chr[256];
	char diskname[BDEVNAME_SIZE] = {0};
	int major, minor;
	int threshold = 0;

	if (count < 1)
		return -EINVAL;

	if (copy_from_user(chr, buf, 256))
		return -EFAULT;

	/* echo "vdb:253:16 1000" > /proc/xxxxx */
	if ((p = strstr(chr, ":"))) {
		memcpy(diskname, chr, (p - chr));
		ret = sscanf(p+1, "%d:%d %d %d", &major, &minor, &threshold, &g_bio_file_info);
		if (ret < 3 || threshold <= 0 || major < 1 || minor < 0) {
			printk("invalid argument \'%s\'\n", chr);
			return -EINVAL;
		}
	} else {
		printk("invalid argument \'%s\'\n", chr);
		return -EINVAL;
	}
	mutex_lock(&rq_hang_buffer_mutex);
	set_disk_type(diskname);
	g_rq_hang_idx = 0;
	memset(g_rq_hang_info, 0x0, sizeof(struct rq_hang_info) * MAX_STORE_RQ_CNT);
	ret = rq_hang_detect(MKDEV(major, minor), threshold);
	mutex_unlock(&rq_hang_buffer_mutex);
	return ret ? ret : count;
}

static int rq_hang_mmap(struct file *file, struct vm_area_struct *vma)
{
	return remap_vmalloc_range(vma, (void *)g_rq_hang_info, vma->vm_pgoff);
}
DEFINE_PROC_ATTRIBUTE_RW(rq_hang);

int disk_hang_init(void)
{
	int ret;
	struct proc_dir_entry *disk_hang_dir = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	sym_blk_mq_queue_tag_busy_iter =
		(fn_queue_tag_busy_iter)kallsyms_lookup_name("blk_mq_queue_tag_busy_iter");
	if (!sym_blk_mq_queue_tag_busy_iter) {
		pr_err("not found symbol \"blk_mq_queue_tag_busy_iter\"\n");
		return -EFAULT;
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	sym_blk_mq_free_request =
		(fn_mq_free_request)kallsyms_lookup_name("__blk_mq_free_request");
	if (!sym_blk_mq_free_request) {
		pr_err("not found symbol \"__blk_mq_free_request\"\n");
		return -EFAULT;
	}
#endif
	sym_get_files_struct =
		(fn_get_files_struct)kallsyms_lookup_name("get_files_struct");
	if (!sym_get_files_struct)
		pr_warn("not found symbol \"get_files_struct\"\n");

	sym_put_files_struct =
		(fn_put_files_struct)kallsyms_lookup_name("put_files_struct");
	if (!sym_put_files_struct)
		pr_warn("not found symbol \"put_files_struct\"\n");

	disk_hang_dir = proc_mkdir(DISKHANG_DIR_NAME, NULL);
	if (!disk_hang_dir) {
		pr_err("create \"/proc/%s\" fail\n", DISKHANG_DIR_NAME);
		return -ENOMEM;
	}
	if (!proc_create_data("rq_hang_detect", 0600, disk_hang_dir,
			      &rq_hang_fops, NULL)) {
		pr_err("create \"/proc/%s/rq_hang_detect\" fail\n",
		       DISKHANG_DIR_NAME);
		ret = -ENOMEM;
		goto remove_proc;
	}
	g_rq_hang_info = vmalloc_user(sizeof(struct rq_hang_info) * MAX_STORE_RQ_CNT);
	if (!g_rq_hang_info) {
		pr_err("alloc memory \"rq hang info buffer\" fail\n");
		ret = -ENOMEM;
		goto remove_proc;
	}
	memset(g_rq_hang_info, 0x0, sizeof(struct rq_hang_info) * MAX_STORE_RQ_CNT);
	pr_info("iosdiag load success\n");
	return 0;
remove_proc:
	remove_proc_subtree(DISKHANG_DIR_NAME, NULL);
	return ret;
}

int disk_hang_exit(void)
{
	if (g_rq_hang_info) {
		vfree(g_rq_hang_info);
		g_rq_hang_info = NULL;
	}
	remove_proc_subtree(DISKHANG_DIR_NAME, NULL);
	return 0;
}

