/*
 * iostat.c for 2.6.* with file /proc/diskstat
 * Linux I/O performance monitoring utility
 */
#include "tsar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <linux/major.h>

char *cg_usage = "    --cg                Linux container stats";

#define MAX_CGROUPS 64
/*Todo,user configure ?*/
#define CGROUP_INFO_AGING_TIME  7200

struct cg_load_info {
	int load_avg_1;
	int load_avg_5;
	int load_avg_15;
	int nr_running;
	int nr_uninterrupt;
};

struct cg_cpu_info {
	unsigned long long cpu_user;
	unsigned long long cpu_nice;
	unsigned long long cpu_sys;
	unsigned long long cpu_idle;
	unsigned long long cpu_iowait;
	unsigned long long cpu_hirq;
	unsigned long long cpu_sirq;
	unsigned long long cpu_steal;
	unsigned long long cpu_guest;
	unsigned long long nr_throttled;
	unsigned long long throttled_time;
};

struct cg_mem_info {

};

struct cg_blkio_info {
    unsigned long long rd_ios;  /* Read I/O operations */
    unsigned long long rd_merges;   /* Reads merged */
    unsigned long long rd_sectors; /* Sectors read */
    unsigned long long rd_ticks;    /* Time in queue + service for read */
    unsigned long long wr_ios;  /* Write I/O operations */
    unsigned long long wr_merges;   /* Writes merged */
    unsigned long long wr_sectors; /* Sectors written */
    unsigned long long wr_ticks;    /* Time in queue + service for write */
    unsigned long long ticks;   /* Time of requests in queue */
    unsigned long long aveq;    /* Average queue length */
};

struct cg_hwres_info {

};

struct cgroup_info {
	char name[LEN_32];
	int valid;
	struct cg_load_info load;
	struct cg_cpu_info cpu;
/*	struct cg_mem_info mem;
	struct cg_blkio_info blkio;*/
} cgroups[MAX_CGROUPS];

unsigned int n_cgs = 0;  /* Number of cgroups */
char buffer[256];       /* Temporary buffer for parsing */

static struct mod_info cg_info[] = {
	/* load info */
	{" load1", HIDE_BIT,  0,  STATS_NULL},
	{" load5", HIDE_BIT,  0,  STATS_NULL},
	{"load15", HIDE_BIT,  0,  STATS_NULL},
	{"  nrun", HIDE_BIT,  0,  STATS_NULL},
	{"nunint", HIDE_BIT,  0,  STATS_NULL},
	/* cpu info */
	{"  user", DETAIL_BIT,  0,  STATS_NULL},
	{"  nice", HIDE_BIT,  0,  STATS_NULL},
	{"   sys", DETAIL_BIT,  0,  STATS_NULL},
	{"  idle", HIDE_BIT,  0,  STATS_NULL},
	{"  wait", HIDE_BIT,  0,  STATS_NULL},
	{"  hirq", HIDE_BIT,  0,  STATS_NULL},
	{"  sirq", HIDE_BIT,  0,  STATS_NULL},
	{" steal", HIDE_BIT,  0,  STATS_NULL},
	{" guest", HIDE_BIT,  0,  STATS_NULL},
        {"nr_throttled", DETAIL_BIT,  0,  STATS_NULL},
        {"throttled_time", DETAIL_BIT,  0,  STATS_NULL},
/* io info */
/*
    {" rrqms", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
    {" wrqms", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
    {" %rrqm", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {" %wrqm", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"    rs", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
    {"    ws", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
    {" rsecs", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
    {" wsecs", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
    {"rqsize", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"rarqsz", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"warqsz", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"qusize", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {" await", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"rawait", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"wawait", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {" svctm", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
    {"  util", SUMMARY_BIT,  MERGE_AVG,  STATS_NULL}
*/
};

#define NR_CGROUP_INFO sizeof(cg_info)/sizeof(struct mod_info)

char *get_cgroup_path(const char *name, const char *child, char *path)
{
	FILE *result;
	char cmd[LEN_256];

	snprintf(cmd, LEN_256, "find /sys/fs/cgroup/%s/ -name %s*", child, name);
	result = popen(cmd, "r");
	if (!result)
		return NULL;

	if (fgets(buffer, sizeof(buffer), result)) {
		sscanf(buffer, "%s", path);
		pclose(result);
		return path;
	}

	pclose(result);
	return NULL;
}

static unsigned long cgroup_init_time;
static int need_reinit(void)
{
	if (cgroup_init_time <= (time(NULL) - CGROUP_INFO_AGING_TIME))
		return 1;

	return 0;
}

static void init_cgroups(void)
{
	int i;
	FILE *result;

	if (n_cgs > 0 && !need_reinit())
		return;

	memset(cgroups, 0, sizeof(cgroups));
	n_cgs = 0;
	result = popen("docker ps -q", "r");
	for (i = 0; i < MAX_CGROUPS && !feof(result); i++) {
		if (feof(result) || !fgets(buffer, sizeof(buffer), result))
			break;
		sscanf(buffer, "%31s", cgroups[n_cgs].name);
		n_cgs++;
	}
	pclose(result);
	cgroup_init_time = time(NULL);
}

static int get_load_and_enhanced_cpu_stats(int cg_idx)
{
	char filepath[LEN_1024];
	FILE *file;
	int items = 0, ret = 0;

	if (!get_cgroup_path(cgroups[cg_idx].name, "cpuacct", filepath))
		return 0;

	strcat(filepath, "/cpuacct.proc_stat");
	file = fopen(filepath, "r");
	if (!file)
		return 0;

	while (fgets(buffer, sizeof(buffer), file)) {
		items += ret;
		if (items == 14)
			break;
		ret = sscanf(buffer, "user %llu", &cgroups[cg_idx].cpu.cpu_user);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "nice %llu", &cgroups[cg_idx].cpu.cpu_nice);
		if (ret != 0) {
			cg_info[6].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "system %llu", &cgroups[cg_idx].cpu.cpu_sys);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "idle %llu", &cgroups[cg_idx].cpu.cpu_idle);
		if (ret != 0) {
			cg_info[8].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "iowait %llu", &cgroups[cg_idx].cpu.cpu_iowait);
		if (ret != 0) {
			cg_info[9].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "irq %llu", &cgroups[cg_idx].cpu.cpu_hirq);
		if (ret != 0) {
			cg_info[10].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "softirq %llu", &cgroups[cg_idx].cpu.cpu_sirq);
		if (ret != 0) {
			cg_info[11].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "steal %llu", &cgroups[cg_idx].cpu.cpu_steal);
		if (ret != 0) {
			cg_info[12].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "guest %llu", &cgroups[cg_idx].cpu.cpu_guest);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "load average(1min) %d", &cgroups[cg_idx].load.load_avg_1);
		if (ret != 0) {
			cg_info[0].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "load average(5min) %d", &cgroups[cg_idx].load.load_avg_5);
		if (ret != 0) {
			cg_info[1].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "load average(15min) %d", &cgroups[cg_idx].load.load_avg_15);
		if (ret != 0) {
			cg_info[2].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "nr_running %d", &cgroups[cg_idx].load.nr_running);
		if (ret != 0) {
			cg_info[3].summary_bit = DETAIL_BIT;
			continue;
		}
		ret = sscanf(buffer, "nr_uninterruptible %d", &cgroups[cg_idx].load.nr_uninterrupt);
		if (ret != 0) {
			cg_info[4].summary_bit = DETAIL_BIT;
			continue;
		}
	}

	fclose(file);
	return items;
}

static int get_cpu_stats(int cg_idx)
{
	char filepath[LEN_1024];
	FILE *file;
	int items = 0, ret = 0;

	if (!get_cgroup_path(cgroups[cg_idx].name, "cpu", filepath))
		return 0;

	strcat(filepath, "/cpu.stat");
	file = fopen(filepath, "r");
	if (!file)
		return 0;

	while (fgets(buffer, sizeof(buffer), file)) {
		items += ret;
		if (items == 2)
			break;
		ret = sscanf(buffer, "nr_throttled %llu", &cgroups[cg_idx].cpu.nr_throttled);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "throttled_time %llu", &cgroups[cg_idx].cpu.throttled_time);
		if (ret != 0) {
			continue;
		}
	}

	fclose(file);
	return items;
}

void get_cgroup_stats(void)
{
	int i, items;

	for (i = 0; i < n_cgs; i++) {
		items = 0;
		items += get_load_and_enhanced_cpu_stats(i);
		items += get_cpu_stats(i);
		cgroups[i].valid = !!items;
	}
}

static int print_cgroup_load(char *buf, int len, struct cg_load_info *info)
{
	return snprintf(buf, len, "%d,%d,%d,%d,%d,",
			info->load_avg_1,
			info->load_avg_5,
			info->load_avg_15,
			info->nr_running,
			info->nr_uninterrupt);
}

static int print_cgroup_cpu(char *buf, int len, struct cg_cpu_info *info)
{
	return snprintf(buf, len, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
			info->cpu_user,
			info->cpu_nice,
			info->cpu_sys,
			info->cpu_idle,
			info->cpu_iowait,
			info->cpu_hirq,
			info->cpu_sirq,
			info->cpu_steal,
			info->cpu_guest,
			info->nr_throttled,
			info->throttled_time);
}

void
print_cgroup_stats(struct module *mod)
{
	int pos = 0, i;
	char buf[LEN_1M];

	memset(buf, 0, LEN_1M);

	for (i = 0; i < n_cgs; i++) {
		if (!cgroups[i].valid)
			continue;
		pos += snprintf(buf + pos, LEN_1M - pos, "%s=",	cgroups[i].name);
		pos += print_cgroup_load(buf + pos, LEN_1M - pos, &cgroups[i].load);
		pos += print_cgroup_cpu(buf + pos, LEN_1M - pos, &cgroups[i].cpu);
		pos += snprintf(buf + pos, LEN_1M - pos, ITEM_SPLIT);
	}
	set_mod_record(mod, buf);
}

void
read_cgroup_stat(struct module *mod, char *parameter)
{
	init_cgroups();
	get_cgroup_stats();
	print_cgroup_stats(mod);
}

static void
set_load_record(double st_array[], U_64 cur_array[])
{
	int i;
	for (i = 0; i < 3; i++) {
		st_array[i] = cur_array[i] / 100.0;
	}
	st_array[3] = cur_array[3];
	st_array[4] = cur_array[4];
}

static void
set_cpu_record(double st_array[],
    U_64 pre_array[], U_64 cur_array[])
{
	int    i, j;
	U_64   pre_total, cur_total;

	pre_total = cur_total = 0;

	for (i = 0; i < 11; i++) {
		if(cur_array[i] < pre_array[i]){
			for(j = 0; j < 11; j++)
				st_array[j] = -1;
			return;
		}

		if (i < 9) {
			pre_total += pre_array[i];
			cur_total += cur_array[i];
		}
	}

	/* no tick changes, or tick overflows */
	if (cur_total <= pre_total) {
		for(j = 0; j < 9; j++)
			st_array[j] = -1;
		return;
	}

	/* set st record */
	for (i = 0; i < 9; i++) {
		st_array[i] = (cur_array[i] - pre_array[i]) * 100.0 / (cur_total - pre_total);
	}
	st_array[9] = (cur_array[9] - pre_array[9]);
	st_array[10] = (cur_array[10] - pre_array[10]);
}

static void
set_cgroup_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
	set_load_record(st_array, cur_array);
	set_cpu_record(&st_array[5], &pre_array[5], &cur_array[5]);
}

void
mod_register(struct module *mod)
{
    register_mod_fields(mod, "--cg", cg_usage, cg_info, NR_CGROUP_INFO, read_cgroup_stat, set_cgroup_record);
}
