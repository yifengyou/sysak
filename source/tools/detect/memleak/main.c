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
#include <pthread.h>

#include "memleak.h"
#include "user_api.h"

extern int read_meminfo(struct meminfo *mem);
extern int slab_main(struct memleak_settings *set);
extern int vmalloc_main(int argc, char **argv);
extern int page_main(struct memleak_settings *set);
static int error = 0;
static int off = 0;
static struct meminfo mem;

static void show_usage(void)
{
	printf("-t \n");
	printf("  slab: trace slab  leak\n");
	printf("  page: trace alloc page  leak\n");
    printf("  vmalloc: trace vmalloc  leak, must use root \n");
	printf("-i: trace internal,default 300s \n");
	printf("-s: stacktrace for memory alloc \n");
	printf("-d: memleak off \n");
	printf("-c: only check memleak,don't diagnose \n");
	printf("-n: trace slab name, defualt select the max size or objects \n");

}

static int memleak_check_only(struct meminfo *mi)
{
    int ret = 0;
    int vmalloc = 0;

    read_meminfo(mi);
    vmalloc = vmalloc_main(0, NULL);
    printf("allocPages:%dM, uslab:%dM vmalloc:%dM\n", (mi->kernel)/1024, mi->uslabkb/1024, vmalloc/1024);
    if (mi->kernel < vmalloc)
        mi->kernel = vmalloc + 1;

    if ((mi->kernel - vmalloc) > 1024*1024*1.5) {
        printf("alloc page memleak\n");
        return MEMLEAK_TYPE_PAGE;
    } else if (mi->uslabkb > 5*1024*1024 ||
                mi->uslabkb > mi->tlmkb*0.15) {
        printf("slab memleak\n");
        return MEMLEAK_TYPE_SLAB;
    } else if (vmalloc > 2*1024 * 1024) {
        printf("vmalloc memleak\n");
        return MEMLEAK_TYPE_VMALLOC;
    }
    return 0;
}

int get_arg(struct memleak_settings *set, int argc, char * argv[])
{
    int ch;

	while ((ch = getopt(argc, argv, "dshci:r:n:t:")) != -1)
	{
		switch (ch)
        {
			case 't':
				if (!strncmp("slab", optarg, 4))
					set->type = MEMLEAK_TYPE_SLAB;
				else if (!strncmp("page", optarg, 4))
					set->type = MEMLEAK_TYPE_PAGE;
				else if (!strncmp("vmalloc", optarg, 7))
					set->type = MEMLEAK_TYPE_VMALLOC;
                break;
			case 'i':
				set->monitor_time = atoi(optarg);
                break;
			case 'r':
				set->rate = atoi(optarg);
                break;
            case 'c':
                memleak_check_only(&mem);
                error = 1;
                break;
			case 'n':
				strncpy(set->name, optarg, NAME_LEN - 1);
                break;
			case 'h':
				show_usage();
				error = 1;
				break;
			case 's':
				set->ext = 1;
				break;
			case 'd':
				off = 1;
				break;
			case '?':
                printf("Unknown option: %c\n",(char)optopt);
				error = 1;
                break;
		}
	}
}


static int memleak_off(void)
{
	int fd = 0;

	fd = open("/dev/sysak", O_RDWR);
    if (fd < 0) {
        printf("open memleak check error\n");
        return -1;
    }
	ioctl(fd, MEMLEAK_OFF);
	close(fd);
	return 0;
}



int main(int argc, char **argv)
{
	struct memleak_settings set;
	int ret = 0;

	memset(&set, 0, sizeof(set));

	get_arg(&set, argc, argv);

	if (error)
		return 0;
	if (off) {
		memleak_off();
		printf("memleak off success\n");
		return 0;
	}
	printf("type %d\n", set.type);

	switch (set.type) {

		case MEMLEAK_TYPE_VMALLOC:
			vmalloc_main(argc, argv);
			break;

		case MEMLEAK_TYPE_PAGE:
			page_main(&set);
			break;

		default:
			slab_main(&set);
			break;
	};
	return 0;
}
