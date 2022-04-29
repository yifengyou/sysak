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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <fcntl.h>
#include <linux/major.h>

char *cg_usage = "    --cg                Linux container stats";

#define MAX_CGROUPS 64
/*Todo,user configure ?*/
#define CGROUP_INFO_AGING_TIME  7200

int nr_cpus;
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

struct cg_memlat_info {
	unsigned long long lat_1;
	unsigned long long lat_5;
	unsigned long long lat_10;
	unsigned long long lat_100;
	unsigned long long lat_500;
	unsigned long long lat_1s;
	unsigned long long lat_over1s;
	unsigned long long total_lat_cnt;
	unsigned long long total_lat_time;
};

struct cg_mem_info {
	unsigned long long cache;
	unsigned long long used;
	unsigned long long limit;
	unsigned long long free;
	unsigned long long util;
	unsigned long long pgfault;
	unsigned long long pgmjfault;
	unsigned long long failcnt;
	struct cg_memlat_info drgl;
	struct cg_memlat_info drml;
	struct cg_memlat_info dcl;
};

struct cg_blkio_info {
	unsigned long long rd_ios;  /* read i/o operations */
	unsigned long long rd_bytes;   /* read i/o bytes */
	unsigned long long rd_wait; /* read i/o wait time */
	unsigned long long rd_time;    /* read i/o service time */
	unsigned long long rd_qios;  /* read i/o queued operations */
	unsigned long long rd_qbytes;   /* read i/o queued bytes */
	unsigned long long wr_ios;  /* read i/o operations */
	unsigned long long wr_bytes;   /* read i/o bytes */
	unsigned long long wr_wait; /* read i/o wait time */
	unsigned long long wr_time;    /* read i/o service time */
	unsigned long long wr_qios;  /* read i/o queued operations */
	unsigned long long wr_qbytes;   /* read i/o queued bytes */
};

struct cg_hwres_info {
	int *cachmis_fds;
	long long *cachmis_cnt;
	long long cachmis_sum;
};

struct cgroup_info {
	char name[LEN_32];
	int valid;
	struct cg_load_info load;
	struct cg_cpu_info cpu;
	struct cg_mem_info mem;
	struct cg_blkio_info blkio;
	struct cg_hwres_info hwres;
} cgroups[MAX_CGROUPS];

unsigned int n_cgs = 0;  /* Number of cgroups */
char buffer[256];       /* Temporary buffer for parsing */

static struct mod_info cg_info[] = {
	/* load info 0-4 */
	{" load1", HIDE_BIT,  0,  STATS_NULL},
	{" load5", HIDE_BIT,  0,  STATS_NULL},
	{"load15", HIDE_BIT,  0,  STATS_NULL},
	{"  nrun", HIDE_BIT,  0,  STATS_NULL},
	{"nunint", HIDE_BIT,  0,  STATS_NULL},
	/* cpu info 5-15 */
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
	/* mem info 16-50*/
	{"  cach", DETAIL_BIT,  0,  STATS_NULL},
	{"  used", DETAIL_BIT,  0,  STATS_NULL},
	{"mtotal", DETAIL_BIT,  0,  STATS_NULL},
	{"  free", DETAIL_BIT,  0,  STATS_NULL},
	{" mutil", SUMMARY_BIT,  0,  STATS_NULL},
	{"pgfault", DETAIL_BIT,  0,  STATS_NULL},
	{"pgmajfault", DETAIL_BIT,  0,  STATS_NULL},
	{"mfailcnt", DETAIL_BIT,  0,  STATS_NULL},
	{" drgl1", HIDE_BIT,  0,  STATS_NULL},
	{" drgl5", HIDE_BIT,  0,  STATS_NULL},
	{"drgl10", HIDE_BIT,  0,  STATS_NULL},
	{"drgl100", HIDE_BIT,  0,  STATS_NULL},
	{"drgl500", HIDE_BIT,  0,  STATS_NULL},
	{"drgl1s", HIDE_BIT,  0,  STATS_NULL},
	{"drgl1s+", HIDE_BIT,  0,  STATS_NULL},
	{"drglcnt", HIDE_BIT,  0,  STATS_NULL},
	{"drgltime", HIDE_BIT,  0,  STATS_NULL},
	{" drml1", HIDE_BIT,  0,  STATS_NULL},
	{" drml5", HIDE_BIT,  0,  STATS_NULL},
	{"drml10", HIDE_BIT,  0,  STATS_NULL},
	{"drml100", HIDE_BIT,  0,  STATS_NULL},
	{"drml500", HIDE_BIT,  0,  STATS_NULL},
	{"drml1s", HIDE_BIT,  0,  STATS_NULL},
	{"drml1s+", HIDE_BIT,  0,  STATS_NULL},
	{"drmlcnt", HIDE_BIT,  0,  STATS_NULL},
	{"drmltime", HIDE_BIT,  0,  STATS_NULL},
	{"  dcl1", HIDE_BIT,  0,  STATS_NULL},
	{"  dcl5", HIDE_BIT,  0,  STATS_NULL},
	{" dcl10", HIDE_BIT,  0,  STATS_NULL},
	{"dcl100", HIDE_BIT,  0,  STATS_NULL},
	{"dcl500", HIDE_BIT,  0,  STATS_NULL},
	{" dcl1s", HIDE_BIT,  0,  STATS_NULL},
	{"dcl1s+", HIDE_BIT,  0,  STATS_NULL},
	{"dclcnt", HIDE_BIT,  0,  STATS_NULL},
	{"dcltime", HIDE_BIT,  0,  STATS_NULL},
	/* io info 51-64*/
	{" riops", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
	{" wiops", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
	{"  rbps", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
	{"  wbps", DETAIL_BIT,  MERGE_SUM,  STATS_NULL},
	{" rwait", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{" wwait", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"  rsrv", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"  wsrv", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"  rioq", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"  wioq", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"rioqsz", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"wioqsz", HIDE_BIT,  MERGE_AVG,  STATS_NULL},
	{"rarqsz", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
	{"warqsz", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
	/* cache miss info 65-66 */
	{"_cahms", DETAIL_BIT,  MERGE_AVG,  STATS_NULL},
	{"cahms", DETAIL_BIT,  0,  STATS_NULL},
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

static int perf_event_init(struct cgroup_info *cgroup)
{
	int cgrp_fd, ret = 0;
	int cpu, *fds;
	long long *counts;
	char path[LEN_256];

	if (!get_cgroup_path(cgroup->name, "perf_event", path))
		return -1;

	cgrp_fd = open(path, O_RDONLY);
	if (cgrp_fd < 0) {
		ret = errno;
		fprintf(stderr, "%s :open %s\n", strerror(errno), path);
		return ret;
	}

	nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	fds = malloc(nr_cpus * sizeof(int));
	if (!fds) {
		fprintf(stderr, "%s :malloc fds fail\n", strerror(errno));
		return -ENOMEM;
	}
	counts = malloc(nr_cpus * sizeof(long long));
	if (!counts) {
		fprintf(stderr, "%s :malloc counsts fail\n", strerror(errno));
		free(fds);
		return -ENOMEM;
	}
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		struct perf_event_attr attr = {
			.type = PERF_TYPE_HARDWARE,
			.freq = 0,
			.disabled = 1,
			.sample_period = 5*1000*1000-1,
			.config = PERF_COUNT_HW_CACHE_MISSES,
		};
		fds[cpu] = syscall(__NR_perf_event_open, &attr, cgrp_fd, cpu, -1, PERF_FLAG_PID_CGROUP);
		if (fds[cpu] < 0) {
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "perf_event_open %s:%d: %s\n",
				cgroup->name, cpu, strerror(errno));
			continue;
		}
		ioctl(fds[cpu], PERF_EVENT_IOC_RESET, 0);
		ioctl(fds[cpu], PERF_EVENT_IOC_ENABLE, 0);
		counts[cpu] = 0;
	}
	cgroup->hwres.cachmis_fds = fds;
	cgroup->hwres.cachmis_cnt = counts;
	return ret;
}

static void init_cgroups(void)
{
	int i, ret;
	FILE *result;

	if (n_cgs > 0 && !need_reinit())
		return;

	memset(cgroups, 0, sizeof(cgroups));
	n_cgs = 0;

	/*check docker exit*/
	if (access("/bin/docker", F_OK) != F_OK &&
		access("/usr/bin/docker", F_OK) != F_OK &&
		access("/bin/docker", F_OK) != F_OK &&
		access("/usr/bin/docker", F_OK) != F_OK) {
		return;
	}

	result = popen("docker ps -q", "r");
	for (i = 0; i < MAX_CGROUPS && !feof(result); i++) {
		if (feof(result) || !fgets(buffer, sizeof(buffer), result))
			break;
		sscanf(buffer, "%31s", cgroups[n_cgs].name);
		ret = perf_event_init(&cgroups[n_cgs]);
		if (ret < 0) {
			fprintf(stderr, "%s:Perf init failed\n", cgroups[n_cgs].name);
		}
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

static int get_mem_latency(FILE *file, struct cg_memlat_info *info)
{
	int items = 0, ret = 0;

	info->total_lat_cnt = 0;
	while (fgets(buffer, sizeof(buffer), file)) {
		items += ret;
		ret = sscanf(buffer, "0-1ms: %llu", &info->lat_1);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_1;
			continue;
		}
		ret = sscanf(buffer, "1-5ms: %llu", &info->lat_5);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_5;
			continue;
		}
		ret = sscanf(buffer, "5-10ms: %llu", &info->lat_10);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_10;
			continue;
		}
		ret = sscanf(buffer, "10-100ms: %llu", &info->lat_100);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_100;
			continue;
		}
		ret = sscanf(buffer, "100-500ms: %llu", &info->lat_500);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_500;
			continue;
		}
		ret = sscanf(buffer, "500-1000ms: %llu", &info->lat_1s);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_1;
			continue;
		}
		ret = sscanf(buffer, ">=1000ms: %llu", &info->lat_over1s);
		if (ret != 0) {
			info->total_lat_cnt += info->lat_1;
			continue;
		}

		ret = sscanf(buffer, "total(ms): %llu", &info->total_lat_time);
		if (ret != 0)
			continue;
	}

	return items;
}

static void set_mem_latency_visible(void)
{
	int i, offset = 24;/* Todo, the idx of memlat_info begin*/
	int cnt = sizeof(struct cg_memlat_info) / sizeof(unsigned long long) * 3;

	for(i = 0; i < cnt; i++)
		cg_info[i + offset].summary_bit = DETAIL_BIT;
}

static int get_memory_stats(int cg_idx)
{
	char filepath[LEN_1024];
	char *path_end = filepath;
	FILE *file;
	int items = 0, ret = 0;
	unsigned long long active_file, inactive_file, usage_in_bytes;

	if (!get_cgroup_path(cgroups[cg_idx].name, "memory", filepath))
		return 0;

	path_end = filepath + strlen(filepath);
	strcpy(path_end, "/memory.stat");
	file = fopen(filepath, "r");
	if (!file)
		return 0;

	while (fgets(buffer, sizeof(buffer), file)) {
		items += ret;
		if (items == 6)
			break;
		ret = sscanf(buffer, "cache %llu", &cgroups[cg_idx].mem.cache);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "pgfault %llu", &cgroups[cg_idx].mem.pgfault);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "pgmjfault %llu", &cgroups[cg_idx].mem.pgmjfault);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "inactive_file %llu", &inactive_file);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "active_file %llu", &active_file);
		if (ret != 0) {
			continue;
		}
		ret = sscanf(buffer, "hierarchical_memory_limit %llu", &cgroups[cg_idx].mem.limit);
		if (ret != 0) {
			continue;
		}
	}

	fclose(file);

	strcpy(path_end, "/memory.usage_in_bytes");
	file = fopen(filepath, "r");
	if (!file)
		return 0;

	fgets(buffer, sizeof(buffer), file);
	ret = sscanf(buffer, "%llu", &usage_in_bytes);
	fclose(file);
	if (ret <=0)
		return 0;
	cgroups[cg_idx].mem.used = usage_in_bytes - inactive_file - active_file;
	cgroups[cg_idx].mem.free = cgroups[cg_idx].mem.limit - usage_in_bytes;

	strcpy(path_end, "/memory.failcnt");
	file = fopen(filepath, "r");
	if (!file)
		return 0;
	fgets(buffer, sizeof(buffer), file);
	ret = sscanf(buffer, "%llu", &cgroups[cg_idx].mem.failcnt);
	fclose(file);
	if (ret <=0)
		return 0;

	strcpy(path_end, "/memory.direct_reclaim_global_latency");
	file = fopen(filepath, "r");
	if (!file)
		return 0;
	ret = get_mem_latency(file, &cgroups[cg_idx].mem.drgl);
	fclose(file);
	if (ret <=0)
		return 0;

	strcpy(path_end, "/memory.direct_reclaim_memcg_latency");
	file = fopen(filepath, "r");
	if (!file)
		return 0;
	ret = get_mem_latency(file, &cgroups[cg_idx].mem.drgl);
	fclose(file);
	if (ret <=0)
		return 0;

	strcpy(path_end, "/memory.direct_compact_latency");
	file = fopen(filepath, "r");
	if (!file)
		return 0;
	ret = get_mem_latency(file, &cgroups[cg_idx].mem.dcl);
	fclose(file);
	if (ret <= 0)
		return 0;

	set_mem_latency_visible();
	return items;
}

static int read_io_stat(const char *filepath, unsigned long long *rval, unsigned long long *wval)
{
	FILE *file;
	char *pbuf;
	int items = 0, ret = 0;

	file = fopen(filepath, "r");
	if (!file)
		return 0;

	while (fgets(buffer, sizeof(buffer), file)) {
		items += ret;
		if (items == 2)
			break;
		pbuf = strstr(buffer, "Read");
		if (pbuf) {
			ret = sscanf(pbuf, "Read %llu", rval);
			if (ret != 1) {
				return 0;
			}
			continue;
		}

		pbuf = strstr(buffer, "Write");
		if (pbuf) {
			ret = sscanf(pbuf, "Write %llu", wval);
			if (ret != 1) {
				return 0;
			}
			continue;
		}
	}

	fclose(file);
	if (items != 2)
		return 0;

	return items;
}

static int get_blkinfo_stats(int cg_idx)
{
	char filepath[LEN_1024];
	char *path_end = filepath;
	int items = 0, ret = 0;

	if (!get_cgroup_path(cgroups[cg_idx].name, "blkio", filepath))
		return 0;

	path_end = filepath + strlen(filepath);
	strcpy(path_end, "/blkio.throttle.io_serviced");
	ret = read_io_stat(filepath, &cgroups[cg_idx].blkio.rd_ios, &cgroups[cg_idx].blkio.wr_ios);
	if (ret <=0)
		return 0;
	items += ret;

	strcpy(path_end, "/blkio.throttle.io_service_bytes");
	ret = read_io_stat(filepath, &cgroups[cg_idx].blkio.rd_bytes, &cgroups[cg_idx].blkio.wr_bytes);
	if (ret <=0)
		return 0;
	items += ret;

	strcpy(path_end, "/blkio.throttle.io_wait_time");
	ret = read_io_stat(filepath, &cgroups[cg_idx].blkio.rd_wait, &cgroups[cg_idx].blkio.wr_wait);
	if (ret <=0)
		return items;
	cg_info[55].summary_bit = DETAIL_BIT;
	cg_info[56].summary_bit = DETAIL_BIT;

	strcpy(path_end, "/blkio.throttle.io_service_time");
	ret = read_io_stat(filepath, &cgroups[cg_idx].blkio.rd_time, &cgroups[cg_idx].blkio.wr_time);
	if (ret <=0)
		return items;
	cg_info[57].summary_bit = DETAIL_BIT;
	cg_info[58].summary_bit = DETAIL_BIT;

	strcpy(path_end, "/blkio.throttle.total_io_queued");
	ret = read_io_stat(filepath, &cgroups[cg_idx].blkio.rd_qios, &cgroups[cg_idx].blkio.wr_qios);
	if (ret <=0)
		return items;
	cg_info[59].summary_bit = DETAIL_BIT;
	cg_info[60].summary_bit = DETAIL_BIT;

	strcpy(path_end, "/blkio.throttle.total_bytes_queued");
	ret = read_io_stat(filepath, &cgroups[cg_idx].blkio.rd_qbytes, &cgroups[cg_idx].blkio.wr_qbytes);
	if (ret <=0)
		return items;

	cg_info[61].summary_bit = DETAIL_BIT;
	cg_info[62].summary_bit = DETAIL_BIT;
	return items;
}

static int get_hwres_stats(int cg_idx)
{
	int i, nr;
	long long sum = 0, count = 0;
	struct cg_hwres_info *hwres;

	hwres = &cgroups[cg_idx].hwres;
	if (!hwres->cachmis_fds || !hwres->cachmis_cnt)
		return 0;	//todo

	for (i = 0; i < nr_cpus; i++) {
		if (hwres->cachmis_fds[i] < 0)
			continue;
		nr = read(hwres->cachmis_fds[i], &count, sizeof(long long));
		if (nr < 0)
			continue;
		hwres->cachmis_cnt[i] = count;
		sum += hwres->cachmis_cnt[i];
	}
	hwres->cachmis_sum = sum;
	return nr_cpus*sizeof(long long);
}

void get_cgroup_stats(void)
{
	int i, items;

	for (i = 0; i < n_cgs; i++) {
		items = 0;
		items += get_load_and_enhanced_cpu_stats(i);
		items += get_cpu_stats(i);
		items += get_memory_stats(i);
		items += get_blkinfo_stats(i);
		items += get_hwres_stats(i);
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

static int print_memlat_info(char *buf, int len, struct cg_memlat_info *info)
{
	return snprintf(buf, len, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
			info->lat_1, info->lat_5, info->lat_10, info->lat_100,
			info->lat_500, info->lat_1s, info->lat_over1s,
			info->total_lat_cnt, info->total_lat_time);
}

static int print_cgroup_memory(char *buf, int len, struct cg_mem_info *info)
{
	int ret;

	ret = snprintf(buf, len, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
			info->cache, info->used, info->limit, info->free,
			info->util, info->pgfault, info->pgmjfault,
			info->failcnt);

	ret += print_memlat_info(buf + ret, len - ret, &info->drgl);
	ret += print_memlat_info(buf + ret, len - ret, &info->drgl);
	ret += print_memlat_info(buf + ret, len - ret, &info->drgl);

	return ret;
}

static int print_cgroup_blkio(char *buf, int len, struct cg_blkio_info *info)
{
	return snprintf(buf, len, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
			info->rd_ios, info->wr_ios,
			info->rd_bytes, info->wr_bytes,
			info->rd_wait, info->wr_wait,
			info->rd_time, info->wr_time,
			info->rd_qios, info->wr_qios,
			info->rd_qbytes, info->wr_qbytes);
}

static int print_cgroup_hwres(char *buf, int len, struct cg_hwres_info *info)
{
	return snprintf(buf, len, "%lld", info->cachmis_sum);
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
		pos += print_cgroup_memory(buf + pos, LEN_1M - pos, &cgroups[i].mem);
		pos += print_cgroup_blkio(buf + pos, LEN_1M - pos, &cgroups[i].blkio);
		pos += print_cgroup_hwres(buf + pos, LEN_1M - pos, &cgroups[i].hwres);
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
set_memory_record(double st_array[], U_64 pre_array[], U_64 cur_array[])
{
	int i;
	int lat_cnt = sizeof(struct cg_memlat_info) / sizeof(unsigned long long) * 3;

	for (i = 0; i < 4; i++) {
		st_array[i] = cur_array[i];
	}

	st_array[4] = cur_array[1] * 100.0 / cur_array[2];

	for (i = 5; i < (lat_cnt + 8); i++) {
		st_array[i] = cur_array[i] - pre_array[i];
	}
}

static void
set_blkio_record(double st_array[], U_64 pre_array[], U_64 cur_array[], int inter)
{
	int i, data_valid = 1;

	for(i = 0; i < 11; i++){
		if(cur_array[i] < pre_array[i]) {
			data_valid = 0;
			break;
		}
	}

	if (!data_valid) {
		for(i = 0; i < 14; i++)
			st_array[i] = -1;
		return;
	}

	unsigned long long rd_ios = cur_array[0] - pre_array[0];
	unsigned long long wr_ios = cur_array[1] - pre_array[1];
	unsigned long long rd_bytes = cur_array[2] - pre_array[2];
	unsigned long long wr_bytes = cur_array[3] - pre_array[3];
	unsigned long long rd_wait = cur_array[4] - pre_array[4];
	unsigned long long wr_wait = cur_array[5] - pre_array[5];
	unsigned long long rd_time = cur_array[6] - pre_array[6];
	unsigned long long wr_time = cur_array[7] - pre_array[7];
	unsigned long long rd_qios = cur_array[8] - pre_array[8];
	unsigned long long wr_qios = cur_array[9] - pre_array[9];
	unsigned long long rd_qbytes = cur_array[10] - pre_array[10];
	unsigned long long wr_qbytes = cur_array[11] - pre_array[11];

	st_array[0] = rd_ios / (inter * 1.0);
	st_array[1] = wr_ios / (inter * 1.0);
	st_array[2] = rd_bytes / (inter * 1.0);
	st_array[3] = wr_bytes / (inter * 1.0);
	st_array[8] = rd_qios / (inter * 1.0);
	st_array[9] = wr_qios / (inter * 1.0);
	st_array[10] = rd_qbytes / (inter * 1.0);
	st_array[11] = wr_qbytes / (inter * 1.0);

	if (rd_ios) {
		st_array[4] = rd_wait / (rd_ios * 1.0);
		st_array[6] = rd_time / (rd_ios * 1.0);
		st_array[12] = rd_bytes / (rd_ios * 1.0);
	} else {
		st_array[4] = 0;
		st_array[6] = 0;
		st_array[12] = 0;
	}

	if (wr_ios) {
		st_array[5] = wr_wait / (wr_ios * 1.0);
		st_array[7] = wr_time / (wr_ios * 1.0);
		st_array[13] = wr_bytes / (wr_ios * 1.0);
	} else {
		st_array[5] = 0;
		st_array[7] = 0;
		st_array[13] = 0;
	}
}

static void
set_hwres_record(double st_array[], U_64 pre_array[], U_64 cur_array[])
{
	st_array[0] = cur_array[1] - pre_array[1];
	st_array[1] = cur_array[1];
}

static void
set_cgroup_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
	set_load_record(st_array, cur_array);
	set_cpu_record(&st_array[5], &pre_array[5], &cur_array[5]);
	set_memory_record(&st_array[16], &pre_array[16], &cur_array[16]);
	set_blkio_record(&st_array[51], &pre_array[51], &cur_array[51], inter);
	set_hwres_record(&st_array[65], &pre_array[65], &cur_array[65]);
}

void
mod_register(struct module *mod)
{
    register_mod_fields(mod, "--cg", cg_usage, cg_info, NR_CGROUP_INFO, read_cgroup_stat, set_cgroup_record);
}
