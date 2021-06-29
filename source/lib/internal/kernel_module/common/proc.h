#ifndef _KERNEL_COMMON_PROC_H
#define _KERNEL_COMMON_PROC_H
#include <linux/proc_fs.h>

extern struct proc_dir_entry *sysak_proc_mkdir(const char *name);
extern struct proc_dir_entry *sysak_proc_create(const char *name,
		const struct file_operations *proc_fops);
extern void sysak_remove_proc_entry(const char *name);
extern int sysak_remove_proc_subtree(const char *name);

extern int sysak_proc_init(void);
extern void sysak_proc_exit(void);
#endif
