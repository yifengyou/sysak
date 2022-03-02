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

struct cgroup_info {
	char name[LEN_32];
	int valid;
	struct cg_load_info load;
/*	struct cg_cpu_info cpu;
	struct cg_mem_info mem;
	struct cg_blkio_info blkio;*/
} cgroups[MAX_CGROUPS];

unsigned int n_cgs = 0;  /* Number of cgroups */
char buffer[256];       /* Temporary buffer for parsing */

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

static struct mod_info cg_info[] = {
	/* load info */
	{" load1", HIDE_BIT,  0,  STATS_NULL},
	{" load5", HIDE_BIT,  0,  STATS_NULL},
	{"load15", HIDE_BIT,  0,  STATS_NULL},
	{"  nrun", HIDE_BIT,  0,  STATS_NULL},
	{"nunint", HIDE_BIT,  0,  STATS_NULL},

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

void get_load_stats(int cg_idx)
{
	char filepath[LEN_1024];
	FILE *file;
	int items;

	if (!get_cgroup_path(cgroups[cg_idx].name, "cpuacct", filepath))
		return;

	strcat(filepath, "/cpuacct.proc_stat");
	file = fopen(filepath, "r");
	if (!file)
		return;

	while (fgets(buffer, sizeof(buffer), file)) {
		items = sscanf(buffer, "load average(1min) %d", &cgroups[cg_idx].load.load_avg_1);
		if (items != 0) {
			cg_info[0].summary_bit = DETAIL_BIT;
			continue;
		}
		items = sscanf(buffer, "load average(5min) %d", &cgroups[cg_idx].load.load_avg_5);
		if (items != 0) {
			cg_info[1].summary_bit = DETAIL_BIT;
			continue;
		}
		items = sscanf(buffer, "load average(15min) %d", &cgroups[cg_idx].load.load_avg_15);
		if (items != 0) {
			cg_info[2].summary_bit = DETAIL_BIT;
			continue;
		}
		items = sscanf(buffer, "nr_running %d", &cgroups[cg_idx].load.nr_running);
		if (items != 0) {
			cg_info[3].summary_bit = DETAIL_BIT;
			continue;
		}
		items = sscanf(buffer, "nr_uninterruptible %d", &cgroups[cg_idx].load.nr_uninterrupt);
		if (items != 0) {
			cg_info[4].summary_bit = DETAIL_BIT;
			continue;
		}
	}

	cgroups[cg_idx].valid = 1;
	fclose(file);
}

void get_cgroup_stats(void)
{
	int i;

	for (i = 0; i < n_cgs; i++) {
		get_load_stats(i);
	}
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
		pos += snprintf(buf + pos, LEN_1M - pos, "%s=%d,%d,%d,%d,%d" ITEM_SPLIT,
			cgroups[i].name,
			cgroups[i].load.load_avg_1,
			cgroups[i].load.load_avg_5,
			cgroups[i].load.load_avg_15,
			cgroups[i].load.nr_running,
			cgroups[i].load.nr_uninterrupt);
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
set_cgroup_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
	set_load_record(st_array, cur_array);
}

void
mod_register(struct module *mod)
{
    register_mod_fields(mod, "--cg", cg_usage, cg_info, NR_CGROUP_INFO, read_cgroup_stat, set_cgroup_record);
}
