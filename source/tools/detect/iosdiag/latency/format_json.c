#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <libgen.h>
#include "iosdiag.h"
#include "format_json.h"
#include <linux/version.h>

#define min(x, y)		((x) > (y) ? (y) : (x))
struct ts_info {
	char *str;
	int idx;
};

struct ts_info g_points[] = {
	{"start", IO_START_POINT},
	{"issue_driver", IO_ISSUE_DRIVER_POINT},
	{"issue_device", IO_ISSUE_DEVICE_POINT},
	{"device_complete", IO_RESPONCE_DRIVER_POINT},
	{"complete", IO_COMPLETE_TIME_POINT},
};

struct ts_info g_delays[] = {
	//{"total", IO_START_POINT},
	{"block", IO_ISSUE_DRIVER_POINT},
	{"driver", IO_ISSUE_DEVICE_POINT},
	{"disk", IO_RESPONCE_DRIVER_POINT},
	{"complete", IO_COMPLETE_TIME_POINT},
};

static char g_check_date[24];

static char *point_idx_to_str(int idx)
{
	int i = 0;

	for (; i < (sizeof(g_points) / sizeof(g_points[0])); i++) {
		if (g_points[i].idx == idx)
			return g_points[i].str;
	}
	return NULL;
}

static char *delay_idx_to_str(int idx)
{
	int i = 0;

	for (; i < (sizeof(g_delays) / sizeof(g_delays[0])); i++) {
		if (g_delays[i].idx == idx)
			return g_delays[i].str;
	}
	return NULL;
}

void set_check_time_date(void)
{
	struct timeval tv;
	struct tm *p;

	gettimeofday(&tv, NULL);
	p = localtime(&tv.tv_sec);
	sprintf(g_check_date, "%d-%d-%d %d:%d:%d.%ld", 
		    1900+p->tm_year,
			1+p->tm_mon,
			p->tm_mday,
			p->tm_hour,
			p->tm_min,
			p->tm_sec,
			tv.tv_usec / 1000);
}

static char *get_check_time_date(void)
{
	return g_check_date;
}

static unsigned long get_total_delay(struct iosdiag_req *iop)
{
	return iop->ts[MAX_POINT - 1] / 1000 - iop->ts[IO_START_POINT] / 1000;
}

static unsigned long get_max_delay(struct iosdiag_req *iop)
{
	int i;
	unsigned long delay;
	unsigned long max_delay = 0;

	for (i = IO_START_POINT + 1; i < MAX_POINT; i++) {
		delay = iop->ts[i] / 1000 - iop->ts[i - 1] / 1000;
		if (max_delay < delay)
			max_delay = delay;
	}
	return max_delay;
}

static char *get_max_delay_component(struct iosdiag_req *iop)
{
	int i, idx = 0;
	unsigned long delay;
	unsigned long max_delay = 0;

	for (i = IO_START_POINT + 1; i < MAX_POINT; i++) {
		delay = iop->ts[i] / 1000 - iop->ts[i - 1] / 1000;
		if (max_delay < delay) {
			max_delay = delay;
			idx = i;
		}
	}
	return idx != 0 ? delay_idx_to_str(idx) : "";
}

static int is_disk_delay(struct iosdiag_req *iop)
{
	if (strcmp(get_max_delay_component(iop), "disk"))
		return 0;
	return 1;
}

void point_convert_to_json(void *dest, void *src)
{
	int i;
	struct iosdiag_req *iop = src;

	sprintf(dest,
			"{\"time\":\"%s\","
			"\"diskname\":\"%s\","
			"\"points\":[", get_check_time_date(), iop->diskname);
	for (i = 0; i < MAX_POINT; i++) {
		if (!iop->ts[i])
			continue;
		sprintf(dest + strlen(dest),
			"{\"point\":\"%s\",\"ts\":%llu}",
			point_idx_to_str(i), (iop->ts[i] / 1000));
		if (i != (MAX_POINT - 1))
			sprintf(dest + strlen(dest), "%s", ",");
	}
	sprintf(dest + strlen(dest), "%s", "]}\n");
}

void delay_convert_to_json(void *dest, void *src)
{
	int i, n;
	int skip = 0;
	unsigned long delay;
	struct iosdiag_req *iop = src;

	sprintf(dest,
			"{\"time\":\"%s\","
			"\"diskname\":\"%s\",",
			get_check_time_date(),
			iop->diskname);
	for (i = 0, n = 0; i < MAX_POINT; i++) {
		if (i == IO_START_POINT) {
			delay = iop->ts[MAX_POINT - 1] / 1000 -
				iop->ts[IO_START_POINT] / 1000;
			sprintf(dest + strlen(dest),
					"\"totaldelay\":%lu,"
					"\"delays\":[",
					delay);
			continue;
		} else {
			if (!skip)
				n = i - 1;
			if (iop->ts[i] > iop->ts[n]) {
				delay = iop->ts[i] / 1000 - iop->ts[n] / 1000;
				skip = 0;
			} else {
				skip = 1;
				continue;
			}
		}
		sprintf(dest + strlen(dest),
			"{\"component\":\"%s\",\"delay\":%lu}",
			delay_idx_to_str(i), delay);
		if (i != (MAX_POINT - 1))
			sprintf(dest + strlen(dest), "%s", ",");
	}
	sprintf(dest + strlen(dest), "%s", "]}\n");
}

void summary_convert_to_json(void *dest, void *src)
{
	char cpu[24] = {0};
	char component[16] = {0};
	struct iosdiag_req *iop = src;
	char *maxdelay_component = get_max_delay_component(iop);
	unsigned long max_delay = get_max_delay(iop);
	unsigned long total_delay = get_total_delay(iop);

	if (!is_disk_delay(iop)) {
		sprintf(component, "os(%s)", maxdelay_component);
		maxdelay_component = component;
	}

	if (iop->cpu[0] == iop->cpu[1] && iop->cpu[1] == iop->cpu[2])
		sprintf(cpu, "%d", iop->cpu[0]);
	else
		sprintf(cpu, "%d -> %d -> %d",
			iop->cpu[0], iop->cpu[1], iop->cpu[2]);
	//blk_rq_op_name(iop->cmd_flags, buf, sizeof(buf));
	sprintf(dest,
			"{\"time\":\"%s\","
			 "\"abnormal\":\"%s delay (%lu:%lu us)\","
			 "\"diskname\":\"%s\","
			 "\"iotype\":\"%s\","
			 "\"sector\":%lu,"
			 "\"datalen\":%u,"
			 "\"comm\":\"%s\","
			 "\"pid\":%d,"
			 "\"cpu\":\"%s\"}\n",
			 get_check_time_date(),
			 maxdelay_component,
			 max_delay,
			 total_delay,
			 iop->diskname,
			 iop->op,
			 iop->sector,
			 iop->data_len,
			 iop->comm,
			 iop->pid,
			 cpu);
}

