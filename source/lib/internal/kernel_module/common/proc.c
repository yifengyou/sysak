#include "common/proc.h"

static struct proc_dir_entry *sysak_root_dir;

static bool check_sysak_root(void)
{
	if (!sysak_root_dir) {
		sysak_root_dir = proc_mkdir("sysak", NULL);
		if (!sysak_root_dir)
			return false;
	}

	return true;
}

struct proc_dir_entry *sysak_proc_mkdir(const char *name)
{
	if (check_sysak_root())
		return proc_mkdir(name, sysak_root_dir);

	return NULL;
}

struct proc_dir_entry *sysak_proc_create(const char *name,
		const struct file_operations *proc_fops)
{
	if (check_sysak_root())
		return proc_create(name, 0644, sysak_root_dir, proc_fops);

	return NULL;
}

void sysak_remove_proc_entry(const char *name)
{
	if (sysak_root_dir)
		remove_proc_entry(name, sysak_root_dir);
}

int sysak_remove_proc_subtree(const char *name)
{
	if (sysak_root_dir)
		return remove_proc_subtree(name, sysak_root_dir);
	return 0;
}

int sysak_proc_init(void)
{
	return 0;
}

void sysak_proc_exit(void)
{
	if (sysak_root_dir)
		proc_remove(sysak_root_dir);
}
