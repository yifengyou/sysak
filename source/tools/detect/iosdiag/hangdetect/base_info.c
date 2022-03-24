#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <libgen.h>
#include "base_info.h"

#define MAX_BDI_CNT	128

static struct base_info g_bi;
static int g_bdi_cnt;
static int g_bni_cnt;
static int g_current_bdi_idx;

static int disk_info_init(struct base_disk_info *bdi, int max_bdi_cnt)
{
	FILE *fp;
	char buf[256] = {0};
	char *cmd = "lsblk -d -P -o NAME,MAJ:MIN";

	if ((fp = popen(cmd, "r")) == NULL) {
		fprintf(stderr, "exec \'%s\' fail\n", cmd);
		return -1;
	}
	while (fgets(buf, sizeof(buf) - 1, fp)) {
		sscanf(buf, "NAME=\"%[^\"]\" MAJ:MIN=\"%d:%d\"",
			    bdi[g_bdi_cnt].diskname,
			    &bdi[g_bdi_cnt].major,
			    &bdi[g_bdi_cnt].minor);
		g_bdi_cnt++;
		if (g_bdi_cnt >= max_bdi_cnt)
			break;
	}
	pclose(fp);
	return 0;
}

static int mnt_info_init(struct base_mnt_info *bni, int max_bni_cnt)
{
	FILE *fp;
	char buf[256] = {0};
	char *cmd = "lsblk -P -o NAME,MOUNTPOINT | grep \"/\"";

	if ((fp = popen(cmd, "r")) == NULL) {
		fprintf(stderr, "exec \'%s\' fail\n", cmd);
		return -1;
	}
	while (fgets(buf, sizeof(buf) - 1, fp)) {
		sscanf(buf, "NAME=\"%[^\"]\" MOUNTPOINT=\"%[^\"]\"",
			    bni[g_bni_cnt].diskname,
			    bni[g_bni_cnt].mnt_dir);
		g_bni_cnt++;
		if (g_bni_cnt >= max_bni_cnt)
			break;
	}
	pclose(fp);
	return 0;
}

static int get_bdi_idx_by_name(char *name)
{
	int i;

	if (!g_bi.bdi)
		return -1;

	for (i = 0; i < MAX_BDI_CNT && g_bi.bdi[i].major; i++)
		if (!strncmp(g_bi.bdi[i].diskname, name,
			     strlen(g_bi.bdi[i].diskname)))
			return i;
	return -1;
}

int set_current_bdi_idx(int idx)
{
	if (idx >= g_bdi_cnt)
		return -1;
	g_current_bdi_idx = idx;
	return 0;
}

int get_current_bdi_idx(void)
{
	return g_current_bdi_idx;
}

int get_bdi_cnt(void)
{
	return g_bdi_cnt;
}

struct base_info *get_base_info_ptr(void)
{
	return &g_bi;
}

struct base_disk_info *get_current_bdi(void)
{
	return &g_bi.bdi[g_current_bdi_idx];
}

char *get_bdi_mnt_dir(char *name)
{
	int i = 0;

	if (!g_bi.bni)
		return NULL;

	for (; i < g_bni_cnt; i++)
		if (!strcmp(g_bi.bni[i].diskname, name))
			return g_bi.bni[i].mnt_dir;
	return NULL;
}

int base_info_init(char *diskname)
{
	int major, minor;
	int current_bdi_idx;
	int size;

	size = MAX_BDI_CNT * sizeof(struct base_disk_info);
	g_bi.bdi = (struct base_disk_info *)malloc(size);
	if (!g_bi.bdi)
		return -ENOMEM;
	memset(g_bi.bdi, 0x0, size);
	disk_info_init(g_bi.bdi, MAX_BDI_CNT);

	size = MAX_BDI_CNT * sizeof(struct base_mnt_info);
	g_bi.bni = (struct base_mnt_info *)malloc(size);
	if (!g_bi.bni)
		return -ENOMEM;
	memset(g_bi.bni, 0x0, size);
	mnt_info_init(g_bi.bni, MAX_BDI_CNT);

	current_bdi_idx = get_bdi_idx_by_name(diskname);
	set_current_bdi_idx(current_bdi_idx);
	return 0;
}

void base_info_exit(void)
{
	if (g_bi.bdi) {
		free(g_bi.bdi);
		g_bi.bdi = NULL;
	}
	if (g_bi.bni) {
		free(g_bi.bni);
		g_bi.bni = NULL;
	}
}

