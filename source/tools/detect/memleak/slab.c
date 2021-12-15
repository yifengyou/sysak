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
static char *slab_name;
static int rate = 20;
static int mark_nr = 0;

#define CALL_SIZE (1000)
static int call_index = 0;

static struct user_call_site *call;

struct user_rcu_exec {
	int pid;
	int err;
	char taskname[32];
	double exec_sum;
};

static inline int is_in(struct user_call_site *call, unsigned long long call_site, int mark)
{
	int i ;
	for (i = 0; i < call_index; i++) {
		if (call[i].call_site == call_site) {
			call[i].nr++;
			call[i].mark_nr += mark;
			mark_nr += mark;
			return 1;
		}
	}

	return 0;
}

static inline int add_count(struct user_call_site *call, struct user_alloc_desc *desc)
{
	int i = 0;

	if (is_in(call, desc->call_site, !!desc->mark))
		return 0;

	if (call_index >= CALL_SIZE) {
		printf("over limit call site\n");
		return 0;
	}

	call[call_index].call_site = desc->call_site;
	call[call_index].nr = 1;
	call[call_index].mark_nr = !!desc->mark;
	mark_nr += !!desc->mark;

	strcpy(call[call_index++].function, desc->function);

	return 0;
}

static int cmp(const void *src, const void *dst)
{
	struct user_call_site *site1 = (struct user_call_site *)src;
	struct user_call_site *site2 = (struct user_call_site *)dst;
	int ret = 0;

	if (mark_nr)
		ret  = site1->mark_nr < site2->mark_nr;
	else
		ret = site1->nr < site2->nr;

	return ret;
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
		printf("%d %8d       %-15s\n", call[num].nr, call[num].mark_nr, call[num].function);


	return 0;
}

int slab_main(struct memleak_settings *set)
{
	int fd = 0;
	int ret = 0;
	struct user_result res;
	struct max_object object;

	struct user_alloc_desc *desc;

	fd = open("/dev/sysak", O_RDWR);
	if (fd < 0) {
		printf("open memleak check error\n");
		return -1;
	}

	if (!set->monitor_time)
		set->monitor_time = detect_time;

	detect_time = set->monitor_time;

	ret = ioctl(fd, MEMLEAK_ON, set);
	if (ret) {
		printf("ioctl error \n", strerror(ret));
		goto _out;
	}

	res.num = 5000;

	res.desc = malloc(res.num * sizeof(struct user_alloc_desc));
	if (!res.desc){
		printf("get result error\n");
		goto _out;
	}

	memset(res.desc, 0, res.num * sizeof(struct user_alloc_desc));
	memset(&object, 0, sizeof(&object));

	res.objects = &object;

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
		int j;
		printf("%s:%-15d  %15s  ptr=%p mark %d delta = %llu\n", desc->comm, desc->pid, desc->function, desc->ptr, desc->mark, desc->ts);
		for(j = 0; j < desc->num; j++)
			printf("%s\n",desc->backtrace[j]);
		printf("\n");
		desc++;
	}

	printf("\n\n");
	printf("未释放内存汇总:\n");
	printf("次数    标记次数       函数\n");
	sort_call_site(&res);

	printf("\n");
	printf("泄漏slab 基本信息:\n");
	printf("slab: %s 总大小: %d\n", object.slabname, object.object_size * object.object_num);
	if (!object.ptr)
		object.similar_object = 0;

	printf("疑似泄漏object: %p 相似object数量: %lu\n", object.ptr, object.similar_object);

	free(res.desc);
_out:
	printf("\n");
	if (call)
		printf("疑似泄漏函数: %s\n", call[0].function);
	else
		printf("疑似泄漏函数: 未知\n");

	ret = ioctl(fd, MEMLEAK_OFF);
	close(fd);

	free(slab_name);
	if (call)
		free(call);

	return 0;
}
