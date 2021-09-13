#ifndef __COMMON__
#define __COMMON__

#define NAME_LEN (128)

#undef TASK_COMM_LEN
#define TASK_COMM_LEN (16)

#define CHR_NAME "sysak"

enum SYSAK_IOCTL_CMD {
	MEMLEAK_IOCTL_CMD = 1,
};

#endif
