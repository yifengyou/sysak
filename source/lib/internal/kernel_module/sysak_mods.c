#include "sysak_mods.h"

int __attribute__((weak)) trace_sig_init(void)
{
	return 0;
}

int __attribute__((weak)) trace_sig_exit(void)
{
	return 0;
}

int __attribute__((weak)) memleak_init(void)
{
	return 0;
}

int __attribute__((weak)) memleak_uninit(void)
{
	return 0;
}

int __attribute__((weak)) trace_irqoff_init(void)
{
	return 0;
}

int __attribute__((weak)) trace_irqoff_exit(void)
{
	return 0;
}

int __attribute__((weak)) task_ctl_init(void)
{
	return 0;
}

int __attribute__((weak)) task_ctl_exit(void)
{
	return 0;
}

struct sysak_module sysak_modules[] = {
	{ "trace_sig", trace_sig_init, trace_sig_exit},
	{ "memleak", memleak_init, memleak_uninit},
	{ "trace_irqoff", trace_irqoff_init, trace_irqoff_exit},
	{ "task_ctl", task_ctl_init, task_ctl_exit},
};

const int sysk_module_num = sizeof(sysak_modules) / sizeof(struct sysak_module);
