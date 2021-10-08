#ifndef SYSAK_MOD_H
#define SYSAK_MOD_H


typedef int(*sysak_module_func)(void);

struct sysak_module {
	char name[16];
	sysak_module_func init;
	sysak_module_func exit;
};

extern struct sysak_module sysak_modules[];
extern const int sysk_module_num;
extern void sysak_module_get(int *mod_ref);
extern void sysak_module_put(int *mod_ref);
extern int sysak_dev_init(void);
extern void sysak_dev_uninit(void);
extern int sysak_bbox_init(void);
extern void sysak_bbox_exit(void);
#endif
