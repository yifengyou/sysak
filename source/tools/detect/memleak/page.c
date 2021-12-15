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


static int detect_time = 300;
static int rate = 20;

#define CALL_SIZE (1000)
static int call_index = 0;

static struct user_call_site *call;

static inline int is_in(struct user_call_site *call, unsigned long long call_site, int page)
{
	int i ;
	for (i = 0; i < call_index; i++) {
		if (call[i].call_site == call_site) {
			call[i].nr++;
			call[i].mark_nr += page;
			return 1;
		}
	}

	return 0;
}

static inline int add_count(struct user_call_site *call, struct user_alloc_desc *desc)
{
	int i = 0;

	if (is_in(call, desc->call_site, 2 << desc->order))
		return 0;

	if (call_index >= CALL_SIZE) {
		printf("over limit call site\n");
		return 0;
	}

	call[call_index].call_site = desc->call_site;
	call[call_index].nr = 1;
	call[call_index].mark_nr = 2 << desc->order;
	strcpy(call[call_index++].function, desc->function);

	return 0;
}

static int cmp(const void *src, const void *dst)
{
	struct user_call_site *site1 = (struct user_call_site *)src;
	struct user_call_site *site2 = (struct user_call_site *)dst;

	return  site1->nr < site2->nr;
}

static int sort_call_site(struct user_result *res)
{
	int num;
	struct user_alloc_desc *desc = res->desc;

	call = malloc(sizeof(*call) * CALL_SIZE);
	if (!call){
		printf("call alloc failed\n");
		return 0;
	}

	memset(call, 0, sizeof(sizeof(*call) * CALL_SIZE));

	for (num = 0; num < res->num; num++) {
		add_count(call, desc + num);
	}

	qsort(call, call_index, sizeof(struct user_call_site), cmp);

	for (num = 0; num < call_index; num++)
		printf("%d %8dK       %s\n", call[num].nr, call[num].mark_nr * 4, call[num].function);


	return 0;
}

int page_main(struct memleak_settings *set)
{
	int fd = 0;
	int ret = 0;
	struct user_result res;

	struct user_alloc_desc *desc;

	fd = open("/dev/sysak", O_RDWR);
	if (fd < 0) {
		printf("open memleak check error\n");
		return -1;
	}

	if (!set->monitor_time)
		set->monitor_time = detect_time;
	set->ext = 1;
	detect_time = set->monitor_time;
	ret = ioctl(fd, MEMLEAK_ON, set);
	if (ret) {
		printf("ioctl error %s \n", strerror(ret));
		goto _out;
	}

	res.num = 5000;

	res.desc = malloc(res.num * sizeof(struct user_alloc_desc));
	if (!res.desc){
		printf("get result error\n");
		goto _out;
	}

	memset(res.desc, 0, res.num * sizeof(struct user_alloc_desc));

	ret = (detect_time + 10) / 10;

	while(ret--) {
		printf("wait for %d seconds \n", ret * 10);
		sleep(10);
	}

_retry:
	ret = ioctl(fd, MEMLEAK_RESULT, &res);
	if (ret) {
		printf("ret %d,errn %d, num = %d\n", ret, errno, res.num);
		sleep(10);
		goto _retry;
	}

	desc = res.desc;
	printf("未释放内存详细列表:\n");
	for (ret = 0; ret < res.num; ret++) {
		int j = 0;
		printf("%s:%d  %s  ptr=%p order %d ts_delta=%llu\n", desc->comm, desc->pid, desc->function, desc->ptr, desc->order, desc->ts);
		for (j = 0; j < desc->num; j++)
			printf("%s\n", desc->backtrace[j]);
		printf("\n");
		desc++;
	}

	printf("\n\n");
	printf("未释放内存汇总:\n");
	printf("次数    总大小       函数\n");
	sort_call_site(&res);

_out:

	free(res.desc);

	ret = ioctl(fd, MEMLEAK_OFF);

	close(fd);
	if (call)
		free(call);
	return 0;
}
