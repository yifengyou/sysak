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

static int jitter_init = 0;
char *jitter_usage = "    --jit                Application jitter stats";
char *mservice_log_dir = "/var/log/sysak/mservice/";
char *runqslow_log_path = "/var/log/sysak/mservice/runqslower";

struct summary {
	unsigned long num;
	unsigned long long total;
	unsigned long long max_value;
	unsigned long long max_stamp;
	int max_cpu, max_pid;
	int lastcpu0, lastcpu1, lastcpu2, lastcpu3;
};

static struct mod_info jitter_info[] = {
	{"   num", HIDE_BIT,  0,  STATS_NULL},		/* total numbers of happend */
	{"  time", HIDE_BIT,  0,  STATS_NULL},		/* the sum-time of delay */
	{" lCPU0", DETAIL_BIT,  0,  STATS_NULL},	/* last happened cpu[0] */
	{" lCPU1", DETAIL_BIT,  0,  STATS_NULL},	/* last happened cpu[1] */
	{" lCPU2", DETAIL_BIT,  0,  STATS_NULL},	/* last happened cpu[2] */
	{" lCPU3", DETAIL_BIT,  0,  STATS_NULL},	/* last happened cpu[3] */
	{"mvalue", DETAIL_BIT,  0,  STATS_NULL},	/* max-delay event value */
	{"mstamp", HIDE_BIT,  0,  STATS_NULL},		/* max-delay event time-stamp */
	{"  mcpu", DETAIL_BIT,  0,  STATS_NULL},	/* max-delay event of cpu */
	{"  mpid", HIDE_BIT,  0,  STATS_NULL},		/* max-delay event of pid */
	{"dltnum", SUMMARY_BIT,  0,  STATS_NULL},	/* delta numbers of happend */
	{" dlttm", SUMMARY_BIT,  0,  STATS_NULL},	/* the delta time of delay */
};

#define NR_JITTER_INFO sizeof(jitter_info)/sizeof(struct mod_info)
struct summary summary;

static int prepare_dictory(char *path)
{
	int ret;

	ret = mkdir(path, 0777);
	if (ret < 0 && errno != EEXIST)
		return errno;
	else
		return 0;
}

static int init_sysak(void)
{
	FILE *fp;
	int ret;

	if (jitter_init)
		return 0;

	ret = prepare_dictory(mservice_log_dir);
	if (ret)
		return ret;

	/* threshold is 40ms */
	fp = popen("sysak runqslower -S -f /var/log/sysak/mservice/runqslower 40000 2>/dev/null &", "r");
	if (!fp) {
		perror("popen");
		return -1;
	}

	jitter_init = 1;
	return 0;
}

void print_jitter_stats(struct module *mod)
{
	FILE *fp;
	char buf[4096], line[4096];

	if((fp = fopen(runqslow_log_path, "r")) == NULL) {
		perror("fopen");
		;/*todo*/
	}

	memset(buf, 0, 4096);
	if (fgets(line, 4096, fp) != NULL) {
		/* "irqoff", "noschd", "rqslow" has 6 charactors */
		sscanf(line+6, "%lu %llu %d %d %d %d %llu %llu %d %d",
			&summary.num, &summary.total,
			&summary.lastcpu0, &summary.lastcpu1,
			&summary.lastcpu2, &summary.lastcpu3,
			&summary.max_value, &summary.max_stamp,
			&summary.max_cpu, &summary.max_pid);
	}

	sprintf(buf, "%lu,%llu,%d,%d,%d,%d,%llu,%llu,%d,%d",
			summary.num, summary.total,
			summary.lastcpu0, summary.lastcpu1,
			summary.lastcpu2, summary.lastcpu3,
			summary.max_value, summary.max_stamp,
			summary.max_cpu, summary.max_pid);
	set_mod_record(mod, buf);
	fclose(fp);
}

void read_jitter_stat(struct module *mod, char *parameter)
{
	int ret;

	ret = init_sysak();
	if (ret)
		;/*todo*/

	print_jitter_stats(mod);
}

static void
set_jitter_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
	st_array[0] = cur_array[0];
	st_array[1] = cur_array[1];
	st_array[2] = cur_array[2];
	st_array[3] = cur_array[3];
	st_array[4] = cur_array[4];
	st_array[5] = cur_array[5];
	st_array[6] = cur_array[6];
	st_array[7] = cur_array[7];

	st_array[8] = cur_array[8];
	st_array[9] = cur_array[9];

	if (cur_array[0] >= pre_array[0])
		st_array[10] = cur_array[0] - pre_array[0];
	else
		st_array[10] = -1;
	if (cur_array[1] >= pre_array[1])
		st_array[11] = cur_array[1] - pre_array[1];
	else
		st_array[11] = -1;
}

void
mod_register(struct module *mod)
{
	register_mod_fields(mod, "--jit", jitter_usage, jitter_info,
			NR_JITTER_INFO, read_jitter_stat, set_jitter_record);
}
