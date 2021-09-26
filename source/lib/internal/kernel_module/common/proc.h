#ifndef _KERNEL_COMMON_PROC_H
#define _KERNEL_COMMON_PROC_H
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#include <asm/uaccess.h>
#include <linux/string.h>

int __weak kstrtobool_from_user(const char __user *s, size_t count, bool *res)
{
	/* Longest string needed to differentiate, newline, terminator */
	char buf[4];

	count = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, s, count))
		return -EFAULT;
	buf[count] = '\0';
	return strtobool(buf, res);
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#define DEFINE_PROC_ATTRIBUTE(name, __write)				\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode));	\
	}								\
									\
	static const struct file_operations name##_fops = {		\
		.owner		= THIS_MODULE,				\
		.open		= name##_open,				\
		.read		= seq_read,				\
		.write		= __write,				\
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
	DEFINE_PROC_ATTRIBUTE(name, name##_write)

#define DEFINE_PROC_ATTRIBUTE_RO(name)	\
	DEFINE_PROC_ATTRIBUTE(name, NULL)
#else
#define DEFINE_PROC_ATTRIBUTE(name, __write)				\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode));	\
	}								\
									\
	static const struct file_operations name##_fops = {		\
		.owner		= THIS_MODULE,				\
		.open		= name##_open,				\
		.read		= seq_read,				\
		.write		= __write,				\
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
	DEFINE_PROC_ATTRIBUTE(name, name##_write)

#define DEFINE_PROC_ATTRIBUTE_RO(name)	\
	DEFINE_PROC_ATTRIBUTE(name, NULL)
#endif


extern struct proc_dir_entry *sysak_proc_mkdir(const char *name);
extern struct proc_dir_entry *sysak_proc_create(const char *name,
		const struct file_operations *proc_fops);
extern void sysak_remove_proc_entry(const char *name);
extern int sysak_remove_proc_subtree(const char *name);

extern int sysak_proc_init(void);
extern void sysak_proc_exit(void);
#endif
