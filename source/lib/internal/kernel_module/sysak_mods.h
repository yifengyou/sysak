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
#endif
