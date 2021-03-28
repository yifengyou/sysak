#ifndef _KERNEL_COMMON_HOOK_H
#define _KERNEL_COMMON_HOOK_H

#include <linux/kprobes.h>
extern int hook_tracepoint(const char *name, void *probe, void *data);
extern int unhook_tracepoint(const char *name, void *probe, void *data);

extern int hook_kprobe(struct kprobe *kp, const char *name,
	kprobe_pre_handler_t pre, kprobe_post_handler_t post);
extern void unhook_kprobe(struct kprobe *kp);

extern int hook_kretprobe(struct kretprobe *ptr_kretprobe, char *kretprobe_func,
	kretprobe_handler_t kretprobe_entry_handler,
	kretprobe_handler_t kretprobe_ret_handler,
	size_t data_size);
extern void unhook_kretprobe(struct kretprobe *ptr_kretprobe);
#endif
