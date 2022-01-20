#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/sysinfo.h>


#define NAME_LEN (128)
#define CALL_SIZE (200)
static int call_index;

struct call_site {
	char funcs[NAME_LEN];
	int nr;
	int size; /* M */
};

static struct call_site call[CALL_SIZE];

static inline int is_exist(char *funcs, int size)
{
    int i ;
    for (i = 0; i < call_index; i++) {
        if (!strncmp(call[i].funcs, funcs, NAME_LEN)) {
            call[i].nr++;
			call[i].size += size;
            return 1;
        }
    }

    return 0;
}

static inline int add_vmalloc(char *funcs, int size)
{
    int i = 0;

    if (is_exist(funcs, size))
        return 0;

    if (call_index >= CALL_SIZE) {
        printf("over limit call site\n");
        return 0;
    }

	strncpy(call[call_index].funcs, funcs, NAME_LEN);

    call[call_index].nr = 1;
	call[call_index++].size = size;

    return 0;
}

static int cmp(const void *site1, const void *site2)
{
	struct call_site * src = (struct call_site *)site1;
	struct call_site * dst = (struct call_site *)site2;

	return src->size < dst->size;
}


int vmalloc_main(int argc, char **argv)
{
	FILE *fd = NULL;
	char addrs[128];
	char funcs[256];
	char lines[512];

	int size = 0;
	int ret = 0;
    unsigned int total = 0;

	fd = fopen("/proc/vmallocinfo", "r");
	if (!fd) {
		printf("open /proc/vmallocinfo error,  use root ?\n");
		return 0;
	}


	while(!feof(fd)) {

		memset(addrs, 0, 128);
		memset(funcs, 0, 256);
		memset(lines, 0, 512);

		if (!fgets(lines, sizeof(lines), fd))
			break;
        if (!strstr(lines,"vmalloc"))
            continue;
		if (sscanf(lines, "%s %d %s", addrs, &size, funcs) != 3)
			continue;

		if (size <= 0)
			continue;

		add_vmalloc(funcs, size);
	}

	qsort(call, call_index, sizeof(struct call_site), cmp);

    if (argc) {
	    printf("VMALLOC 未释放函数汇总:\n");
	    printf("次数   总大小              函数\n");
    }
	for (ret = 0; ret < call_index; ret++) {
        total += (call[ret].size >> 10);
		if (argc && call[ret].size >> 20)
			printf("%d   %2dMB               %s \n", call[ret].nr, call[ret].size >> 20, call[ret].funcs);
	}

	fclose(fd);
    return total;
}







