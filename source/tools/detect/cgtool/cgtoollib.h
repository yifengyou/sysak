#ifndef __CGTRACELIB_H
#define __CGTRACELIB_H

#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdio.h>

#define CMD_LEN 4096
#define SYM_LEN 1024

static int get_dir_by_knid(unsigned int kn_id, char *sub, char *buf, unsigned int size)
{
	FILE *fp = NULL;
	char cmd[CMD_LEN];

	sprintf(cmd, "find /sys/fs/cgroup/%s/ -inum %u", sub, kn_id);

	fp = popen(cmd, "r");
	if (fp == NULL)
		return -1;
	      
	fgets(buf, size, fp);

	pclose(fp);

	return 0;
}

static unsigned int get_knid_by_dir(char *dir)
{
	struct stat buf;
	stat(dir, &buf);

	return buf.st_ino;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static bool find_ksym_by_name(const char *name)
{
	FILE *fp = NULL;
	char cmd[CMD_LEN];
	char buf[SYM_LEN] = "\0";

	sprintf(cmd, "FIND_KSYM=`echo %s |awk -F'kprobe_' '{print $2}'`; cat /proc/kallsyms |grep -w $FIND_KSYM", name);

	fp = popen(cmd, "r");
	if (fp == NULL)
		return false;

	fgets(buf, SYM_LEN, fp);

	pclose(fp);

	if (strlen(buf) == 0)
		return false;
	else
		return true;
}

#endif
