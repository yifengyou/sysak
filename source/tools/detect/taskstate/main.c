#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>

#define MAX_PATH_LEN 200
#define MAX_LINE_LEN 300
#define TASK_NAME_KEY "Name"
#define TASK_STATE_KEY "State"
#define TASK_RUNNING "running"
#define TASK_UNINTERRUPT "disk sleep"

static char g_rtask_file[MAX_PATH_LEN] = {0};
static char g_dtask_file[MAX_PATH_LEN] = {0};
static FILE *g_rtask_fp;
static FILE *g_dtask_fp;

static void usage(void)
{
	fprintf(stdout,
			"sysak taskstate: get tasks whose states are running or uninterruptible\n"
			"options: -h, help information\n"
			"         -r file, get tasks whose states are running and output result to file\n"
			"         -d file, get tasks whose states are uninterruptible and output result to file\n");
	exit(-1);
}

static void parse_arg(int argc, char *argv[])
{
	int ch;

	//printf("argc:%d\n", argc);

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "r:d:h")) != -1) {
		switch (ch) {
			case 'r':
				if (optarg && (strlen(optarg) < MAX_PATH_LEN))
					strncpy(g_rtask_file, optarg, strlen(optarg));
				else
					exit(-1);
				break;
			case 'd':
				if (optarg && (strlen(optarg) < MAX_PATH_LEN))
					strncpy(g_dtask_file, optarg, strlen(optarg));
				else
					exit(-1);
				break;
			case 'h':
			default:
				usage();
				break;
		}
	}

	if (!g_rtask_file[0] || !g_dtask_file[0])
		exit(-1);
}

static void get_dtask_stack(long tid)
{
	char line[MAX_LINE_LEN] = {0};
	FILE *fp;
	char path[MAX_PATH_LEN] = {0};

	snprintf(path, sizeof(path), "/proc/%ld/stack", tid);

	fp = fopen(path, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {

		fwrite(line, strlen(line), 1, g_dtask_fp);
	}

	fclose(fp);
}

static int get_task_info(long pid)
{
	struct dirent *dirp;
	DIR *dp;
	char path[MAX_PATH_LEN] = {0};
	char tid_str[MAX_PATH_LEN] = {0};
	char line[MAX_LINE_LEN] = {0};
	char task_name[MAX_LINE_LEN] = {0};
	long tid;
	FILE *fp;
	char *start;

	snprintf(path, sizeof(path), "/proc/%ld/task", pid);

	if (!(dp = opendir(path))) {
		return -1;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_type == DT_DIR) {

			tid = atol(dirp->d_name);
			snprintf(path, sizeof(path), "/proc/%ld/status", tid);

			fp = fopen(path, "r");
			if (!fp)
				continue;

			while (fgets(line, sizeof(line), fp)) {

				if ((start = strstr(line, TASK_NAME_KEY)) && (start == line)) {
					strcpy(task_name, line);
					continue;
				}

				if ((start = strstr(line, TASK_STATE_KEY)) && (start == line)) {

					if (strstr(line, TASK_RUNNING)) {
						snprintf(tid_str, sizeof(tid_str), "%ld\n", tid);
						fwrite(tid_str, strlen(tid_str), 1, g_rtask_fp);
						fwrite(task_name, strlen(task_name), 1, g_rtask_fp);
					//	fwrite(line, strlen(line), 1, g_rtask_fp);
					}
					else if (strstr(line, TASK_UNINTERRUPT)) {
						snprintf(tid_str, sizeof(tid_str), "%ld\n", tid);
						fwrite(tid_str, strlen(tid_str), 1, g_dtask_fp);
						fwrite(task_name, strlen(task_name), 1, g_dtask_fp);
					//	fwrite(line, strlen(line), 1, g_dtask_fp);
						get_dtask_stack(tid);
					}

					break;
				}
			}

			fclose(fp);
		}
	}

	closedir(dp);
	return 0;
}

static int scan_task(void)
{
	struct dirent *dirp;
	DIR *dp;
	int i;
	int len;
	long pid;

	if (!(dp = opendir("/proc"))) {
		return -1;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_type == DT_DIR) {
			len = strlen(dirp->d_name);

			for (i = 0; dirp->d_name[i] != 0; ++i) {
				if (!isdigit(dirp->d_name[i]))
					break;
			}

			if (len != i)
				continue;

			pid = atol(dirp->d_name);

			get_task_info(pid);

		}
	}

	closedir(dp);
//	printf("\n");
	return 0;
}

int main(int argc, char *argv[])
{
	parse_arg(argc, argv);

	g_rtask_fp = fopen(g_rtask_file, "w+");
	if (!g_rtask_fp) {
		exit(-1);
	}

	g_dtask_fp = fopen(g_dtask_file, "w+");
	if (!g_dtask_fp) {
		fclose(g_rtask_fp);
		exit(-1);
	}

	scan_task();

close_file:
	fclose(g_dtask_fp);
	fclose(g_rtask_fp);
	return 0;
}
