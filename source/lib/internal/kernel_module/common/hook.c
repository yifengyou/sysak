/*
 * hook.c
 */
#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/cpu.h>
#include <linux/tracepoint.h>
#include "common/hook.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
int hook_tracepoint(const char *name, void *probe, void *data)
{
	return tracepoint_probe_register(name, probe);
}

int unhook_tracepoint(const char *name, void *probe, void *data)
{
	int ret = 0;

	do {
		ret = tracepoint_probe_unregister(name, probe);
	} while (ret == -ENOMEM);

        return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
int hook_tracepoint(const char *name, void *probe, void *data)
{
	return tracepoint_probe_register(name, probe, data);
}

int unhook_tracepoint(const char *name, void *probe, void *data)
{
	int ret = 0;

	do {
		ret = tracepoint_probe_unregister(name, probe, data);
	} while (ret == -ENOMEM);

	return ret;
}
#else
static struct tracepoint *tp_ret;
static void probe_tracepoint(struct tracepoint *tp, void *priv)
{
	char *n = priv;

	if (strcmp(tp->name, n) == 0)
		tp_ret = tp;
}

static struct tracepoint *find_tracepoint(const char *name)
{
	tp_ret = NULL;
	for_each_kernel_tracepoint(probe_tracepoint, (void *)name);

	return tp_ret;
}

int hook_tracepoint(const char *name, void *probe, void *data)
{
	struct tracepoint *tp;

	tp = find_tracepoint(name);
	if (!tp)
		return 0;

	return tracepoint_probe_register(tp, probe, data);
}

int unhook_tracepoint(const char *name, void *probe, void *data)
{
	struct tracepoint *tp;
	int ret = 0;

	tp = find_tracepoint(name);
	if (!tp)
		return 0;

	do {
		ret = tracepoint_probe_unregister(tp, probe, data);
	} while (ret == -ENOMEM);

	return ret;
}
#endif

int hook_kprobe(struct kprobe *kp, const char *name,
		kprobe_pre_handler_t pre, kprobe_post_handler_t post)
{
	kprobe_opcode_t *addr;

	if (!name || strlen(name) >= 255)
		return -EINVAL;
	addr = (kprobe_opcode_t *)kallsyms_lookup_name(name);
	if (!addr)
		return -EINVAL;

	memset(kp, 0, sizeof(struct kprobe));
	kp->symbol_name = name;
	kp->pre_handler = pre;
	kp->post_handler = post;

	register_kprobe(kp);

	return 0;
}

void unhook_kprobe(struct kprobe *kp)
{
	if (kp->symbol_name != NULL)
		unregister_kprobe(kp);

	memset(kp, 0, sizeof(struct kprobe));
}

int hook_kretprobe(struct kretprobe *ptr_kretprobe, char *kretprobe_func,
	kretprobe_handler_t kretprobe_entry_handler,
	kretprobe_handler_t kretprobe_ret_handler,
	size_t data_size)
{
	memset(ptr_kretprobe, 0, sizeof(struct kretprobe));
	ptr_kretprobe->kp.symbol_name = kretprobe_func;
	ptr_kretprobe->handler = kretprobe_ret_handler;
	ptr_kretprobe->entry_handler = kretprobe_entry_handler;
	ptr_kretprobe->data_size = data_size;
	ptr_kretprobe->maxactive = 200;

	return register_kretprobe(ptr_kretprobe);
}

void unhook_kretprobe(struct kretprobe *ptr_kretprobe)
{
	if (!ptr_kretprobe->kp.addr)
		return;

	unregister_kretprobe(ptr_kretprobe);
	memset(ptr_kretprobe, 0, sizeof(struct kretprobe));
}

