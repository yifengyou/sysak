#ifndef _RTRACE_COMMON_USR_H
#define _RTRACE_COMMON_USR_H
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "common.def.h"

extern bool gdebug;

#define pr_err(fmt, ...)                      \
    do                                        \
    {                                         \
        printf("ERROR: " fmt, ##__VA_ARGS__); \
    } while (0)

#define pr_dbg(fmt, ...)                          \
    do                                            \
    {                                             \
        if (gdebug)                               \
            printf("DEBUG: " fmt, ##__VA_ARGS__); \
    } while (0)

#ifndef zfree
#define zfree(ptr) ( \
    {                \
        free(*ptr);  \
        *ptr = NULL; \
    })
#endif

#ifndef zclose
#define zclose(fd) (              \
    {                             \
        int ___err = 0;           \
        if ((fd) >= 0)            \
            ___err = close((fd)); \
        fd = -1;                  \
        ___err;                   \
    })
#endif

#define DEBUG_LINE printf("debug: %s:%d:1 fun:%s\n", __FILE__, __LINE__, __FUNCTION__);
#define ERROR_LINE printf("error: %s:%d:1 fun:%s\n", __FILE__, __LINE__, __FUNCTION__);

static char special_funcs[][50] = {
    "tcp_sendmsg",
    "tcp_cleanup_rbuf",
    "kretprobe_common",
    "kprobe_lines",
    "raw_sendmsg",
};

static inline bool is_special_func(char *func)
{
    int i;
    int len = sizeof(special_funcs) / sizeof(special_funcs[0]);

    for (i = 0; i < len; i++)
        if (strcmp(func, special_funcs[i]) == 0)
            return true;
    return false;
}

#endif
