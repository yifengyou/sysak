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
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
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
