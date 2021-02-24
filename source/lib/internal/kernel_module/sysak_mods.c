#include "sysak_mods.h"

extern int trace_sig_init(void);
extern int trace_sig_exit(void);
extern int memleak_init(void);
extern int memleak_uninit(void);
extern int trace_irqoff_init(void);
extern int trace_irqoff_exit(void);

struct sysak_module sysak_modules[] = {
	{ "trace_sig", trace_sig_init, trace_sig_exit},
	{ "memleak", memleak_init, memleak_uninit},
	{ "trace_irqoff", trace_irqoff_init, trace_irqoff_exit},
};

const int sysk_module_num = sizeof(sysak_modules) / sizeof(struct sysak_module);
