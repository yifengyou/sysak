#ifndef KERNEL_COMMON_HOOK_H

extern int hook_tracepoint(const char *name, void *probe, void *data);
extern int unhook_tracepoint(const char *name, void *probe, void *data);
#endif
