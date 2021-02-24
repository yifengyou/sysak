#include "sysak_mods.h"

extern int test_init(void);
extern int test_exit(void);

struct sysak_module sysak_modules[] = {
	{ "test_module", test_init, test_exit},
};

const int sysk_module_num = sizeof(sysak_modules) / sizeof(struct sysak_module);
