#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/cpumask.h>
#include <linux/mm_types.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include <asm/syscall.h>
#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include "common.h"

static DEFINE_MUTEX(dev_mutex);
static int sysak_dev_major = -1;
static struct class *sysak_dev_class = NULL;
static struct device *sysak_dev = NULL;

struct sysak_dev {
	struct cdev cdev;
};

int __attribute__((weak)) memleak_handler_cmd(int cmd, unsigned long arg)
{
	return -ENOSYS;
}

static long sysak_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	int type, nr;

	if (!mutex_trylock(&dev_mutex))
		return -EBUSY;

	type = _IOC_TYPE(cmd);
	nr = _IOC_NR(cmd);
	switch (type) {
		case MEMLEAK_IOCTL_CMD:
			ret = memleak_handler_cmd(nr, arg);
			break;
		default:
			printk("defualt ioctl cmd =%d, nr = %d\n", type, nr);
			break;
	}

	mutex_unlock(&dev_mutex);
	return ret;
}

static int sysak_open(struct inode *inode, struct file *file)
{
	if (!mutex_trylock(&dev_mutex))
		return -EBUSY;
	__module_get(THIS_MODULE);
	printk("sysak open\n");
	mutex_unlock(&dev_mutex);

	return 0;
}

static int sysak_release(struct inode *inode, struct file *file)
{

	if (!mutex_trylock(&dev_mutex))
		return -EBUSY;

	printk("sysak close\n");
	module_put(THIS_MODULE);
	mutex_unlock(&dev_mutex);
	return 0;
}

static const struct file_operations sysak_fops = {
	.open       = sysak_open,
	.release    = sysak_release,
	.unlocked_ioctl = sysak_ioctl,
};

static char *sysak_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = S_IRUGO | S_IRWXUGO | S_IALLUGO;

	return kstrdup("sysak", GFP_KERNEL);;
}

int sysak_dev_init(void)
{
	int ret = 0;

	sysak_dev_major = register_chrdev(0, CHR_NAME, &sysak_fops);;

	if (sysak_dev_major < 0) {
		printk("sysak: failed to register device\n");
		return sysak_dev_major;
	}

	sysak_dev_class = class_create(THIS_MODULE, CHR_NAME);
	if (IS_ERR(sysak_dev_class)) {
		ret = PTR_ERR(sysak_dev_class);
		printk(KERN_ERR "sysak: class_create err=%d", ret);
		unregister_chrdev(sysak_dev_major, CHR_NAME);

		return ret;
	}
	sysak_dev_class->devnode = sysak_devnode;

	sysak_dev = device_create(sysak_dev_class, NULL, MKDEV(sysak_dev_major, 0), NULL, CHR_NAME);
	if (IS_ERR(sysak_dev)) {
		ret = PTR_ERR(sysak_dev);
		printk(KERN_ERR "sysak: device_create err=%d", ret);
		unregister_chrdev(sysak_dev_major, CHR_NAME);
		class_destroy(sysak_dev_class);

		return ret;
	}

	return 0;
}

void sysak_dev_uninit(void)
{
	if (sysak_dev_major >= 0)
	        unregister_chrdev(sysak_dev_major, CHR_NAME);

	if (sysak_dev != NULL)
		device_destroy(sysak_dev_class, MKDEV(sysak_dev_major, 0));

	if (sysak_dev_class != NULL)
		class_destroy(sysak_dev_class);

	sysak_dev_major = -1;
	sysak_dev = NULL;
	sysak_dev_class = NULL;
}
