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
static int need_exit = 0;
static int mark_nr = 0;

#define CALL_SIZE (100)
static int call_index = 0;

struct user_call_site *call;

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
		printf("%d %8d       %s\n", call[num].nr, call[num].mark_nr, call[num].function);


	return 0;
}


int memleak_rcuos_execsum(struct user_rcu_exec *sum, char *taskname, int pid)
{
	int i;
	char name[256] = {0};
	char sumname[NAME_LEN];
	double sumtime;
	char tmp;

	FILE *file = NULL;

	i = snprintf(name, NAME_LEN, "%s/%d/%s", "/proc", pid, "sched");
	file = fopen(name, "r");
	if (!file) {
		printf("open rcuos file %s failed \n", name);
		return 0;
	}

	memset(name, 0, 256);

	while(!feof(file)) {
		if(!fgets(name, sizeof(name), file))
			break;

		if (!strstr(name, "se.sum_exec_runtime"))
			continue;

		if(sscanf(name, "%s %c %lf", &sumname, &tmp, &sumtime) != 3)
			break;

		//printf("task %s current %lf prev %lf\n", sum->taskname, sumtime, sum->exec_sum);

		if (!sum->exec_sum) {
			sum->exec_sum = sumtime;
			sum->pid = pid;
			strncpy(sum->taskname, taskname, 31);
			goto _out;
		}

		if (sum->exec_sum == sumtime) {
			sum->err = 1;
			goto _out;
		}
		break;
	}

_out:
	fclose(file);
	return 0;
}

void * memleak_check_rcu(void *argv)
{
    DIR *dp;
    struct dirent *entry;
	char rcuos[NAME_LEN];
	char taskname[64];
	struct user_rcu_exec *sum, *tmp;
	int cpu = 0;
	int ret = 0;
	int fd = 0;
	int i = 0;

	cpu = get_nprocs_conf();
	if (cpu <= 0)
		return NULL;

	sum = (struct user_rcu_exec *)malloc(sizeof(*sum) * cpu);
	if (!sum) {
		printf("alloc memory failed\n");
		return NULL;
	}

	tmp = sum;
	memset(sum, 0, sizeof(*sum) * cpu);

    dp = opendir("/proc");
    if (!dp) {
		printf("open proc error\n");
		return NULL;
	}

	while ((entry = readdir(dp)) != NULL)
	{
		if ((strcmp(entry->d_name, ".") == 0) ||
				    (strcmp(entry->d_name, "..") == 0) ||
				    (atoll(entry->d_name) <= 0)) {
			    continue;
		 }

		memset(rcuos, 0, NAME_LEN);

		ret = snprintf(rcuos, NAME_LEN, "%s/%s/%s", "/proc/", entry->d_name, "comm");
		fd = open(rcuos, O_RDONLY);
		if (fd < 0)
			continue;

		memset(taskname, 0, 64);

		ret = read(fd, taskname, 64);
		if (strncmp("rcuos/", taskname, 6)) {
			close(fd);
			continue;
		}

		taskname[ret - 1 ] = 0;

		if (i < cpu) {
			memleak_rcuos_execsum(tmp + i, taskname, atoi(entry->d_name));
			i++;
		}
	}

	sleep(detect_time/3);

	tmp = sum;
	for (i = 0; i < cpu; i++) {

		memleak_rcuos_execsum(tmp, tmp->taskname, tmp->pid);

		if (tmp->err) {
			printf("task %s %d hang\n", tmp->taskname, tmp->pid);
			need_exit = 1;
		}
		tmp++;
	}

	closedir(dp);

	return NULL;
}

int slab_main(struct memleak_settings *set)
{
	int fd = 0;
	int ret = 0;
	struct user_result res;
	struct max_object object;

	struct user_alloc_desc *desc;
	pthread_t pid;

	ret =  pthread_create(&pid, NULL, memleak_check_rcu, NULL);
	if (ret) {
		printf("create rcu thread error \n");
	}

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
		if (need_exit) {
			printf("rcuos check faild \n");
			goto _out;
		}

	}

	ret = ioctl(fd, MEMLEAK_RESULT, &res);
	if (ret) {
		printf("ret %d,errn %d, num = %d\n", ret, errno, res.num);
		goto _out;
	}

	desc = res.desc;
	printf("未释放内存详细列表:\n");
	for (ret = 0; ret < res.num; ret++) {
		printf(" %s:%d  %s  ptr=%p mark %d\n", desc->comm, desc->pid, desc->function, desc->ptr, desc->mark);
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
	printf("RCUOS 线程检测: %s\n", need_exit ? "异常" : "通过");

	if (call && mark_nr)
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
