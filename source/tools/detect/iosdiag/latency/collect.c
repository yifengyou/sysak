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
#include <libgen.h>
#include "ebpf_load.h"
#include "iosdiag.h"
#include "format_json.h"
#include <linux/version.h>

#define min(x, y)		((x) > (y) ? (y) : (x))

#define DECLEAR_BPF_OBJ(name)					\
	static struct name##_bpf *name;				\
	static int name##_bpf_load;				\

DECLEAR_BPF_OBJ(iosdiag_virtblk);
DECLEAR_BPF_OBJ(iosdiag_nvme);
DECLEAR_BPF_OBJ(iosdiag_scsi);
static int iosdiag_map;
static int iosdiag_virtblk_map;
static int iosdiag_maps_targetdevt;
static int g_stop;

extern unsigned long get_threshold_us(void);
static int exec_shell_cmd(char *cmd)
{
	char buf[64];
	FILE *fp;

	if (!cmd)
		return -1;

	if ((fp = popen(cmd, "r")) == NULL) {
		fprintf(stderr, "exec \'%s\' fail\n", cmd);
		return -1;
	}

	while (fgets(buf, sizeof(buf) - 1, fp));
	pclose(fp);
	return 0;
}

static int over_threshold(struct iosdiag_req *iop)
{
	unsigned long threshold_ns = get_threshold_us() * 1000;
	unsigned long delay_ns = iop->ts[IO_COMPLETE_TIME_POINT] -
				iop->ts[IO_START_POINT];

	if (threshold_ns && delay_ns >= threshold_ns)
		return 1;
	return 0;
}

static void iosdiag_store_result(int fd)
{
	struct iosdiag_key key, next_key;
	struct iosdiag_req iop;
	unsigned long sleep_us = get_threshold_us() ? get_threshold_us() : 1000;
	char *buf;
	int i = 0;
	unsigned int seq = 0;

	printf("running...");
	fflush(stdout);
	buf = malloc(JSON_BUFFER_SIZE);
	memset(buf, 0x0, JSON_BUFFER_SIZE);
	while (!g_stop) {
		if (bpf_map_get_next_key(iosdiag_map, &key, &next_key) == 0) {
			bpf_map_lookup_elem(iosdiag_map, &next_key, &iop);
			if (iop.complete) {
				if (over_threshold(&iop)) {
					seq++;
					set_check_time_date();
					summary_convert_to_json(buf, &iop, seq);
					delay_convert_to_json(buf + strlen(buf), &iop, seq);
					write(fd, buf, strlen(buf));
				}
				bpf_map_delete_elem(iosdiag_map, &next_key);
			}
			key = next_key;
			if (i++ > 50) {
				usleep(sleep_us);
				i = 0;
			}
		} else
			usleep(sleep_us);
	}
	free(buf);
	printf("done\n");
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        //return vfprintf(stderr, format, args);
	return 0;
}

static void iosdiag_stop(int signo)
{
    //printf("iosdiag stop!\n");
    g_stop = 1;
}

#define LOAD_IOSDIAG_BPF(name, load_map)							\
({												\
	__label__ out;										\
	int __ret = 0;										\
	printf("start %s load bpf\n", #name);							\
	name = name##_bpf__open();								\
	if (!name) {										\
		printf("load bpf error\n");							\
		printf("load %s bpf fail\n", #name);						\
		__ret = -1;									\
		goto out;									\
	}											\
	if (name##_bpf__load(name)) {								\
		printf("load bpf prog error\n");						\
		printf("load %s bpf fail\n", #name);						\
		name##_bpf__destroy(name);							\
		__ret = -1;									\
		goto out;									\
	}											\
	if (name##_bpf__attach(name)) {								\
		printf("attach bpf prog error\n");						\
		printf("load %s bpf fail\n", #name);						\
		name##_bpf__destroy(name);							\
		__ret = -1;									\
		goto out;									\
	}											\
	if (load_map) {										\
		iosdiag_map = bpf_map__fd(name->maps.iosdiag_maps);				\
		iosdiag_maps_targetdevt = bpf_map__fd(name->maps.iosdiag_maps_targetdevt);	\
	}											\
	if (!__ret)										\
		printf("load %s bpf success\n", #name);						\
	name##_bpf_load = 1;									\
out:												\
	__ret;											\
})

static unsigned int get_devt_by_devname(char *devname)
{
	char sys_file[64];
	char cmd[128];
	char dev[16];
	FILE *fp;
	int major, minor;

	sprintf(sys_file, "/sys/block/%s/dev", devname);
	if (access(sys_file, F_OK))
		sprintf(sys_file, "/sys/block/*/%s/../dev", devname);
	
	sprintf(cmd, "cat %s 2>/dev/null", sys_file);
	if ((fp = popen(cmd, "r")) == NULL) {
		fprintf(stderr, "exec \'%s\' fail\n", cmd);
		return 0;
	}

	while (fgets(dev, sizeof(dev) - 1, fp)) {
		if (sscanf(dev, "%d:%d", &major, &minor) != 2) {
			pclose(fp);
			return 0;
		}
	}
	pclose(fp);
	return ((major << 20) | minor);
}

static char *get_module_name_by_devname(char *devname)
{
	char sys_file[64] = {0};
	char file_path[PATH_MAX] = {0};
	int ret;

	sprintf(sys_file, "/sys/class/block/%s", devname);
	ret = readlink(sys_file, file_path, PATH_MAX);
	if (ret < 0 || ret >= PATH_MAX)
		return "none";
	if (strstr(file_path, "virtio"))
		return "virtblk";
	else if (strstr(file_path, "nvme"))
		return "nvme";
	else if (strstr(file_path, "target"))
		return "scsi";
	return "none";
}

int iosdiag_init(char *devname)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int key = 0;
	unsigned int target_devt = get_devt_by_devname(devname);
	char *module_name = get_module_name_by_devname(devname);

	setrlimit(RLIMIT_MEMLOCK, &r);

	libbpf_set_print(libbpf_print_fn);
	if (!strcmp(module_name, "virtblk")) {
		if (LOAD_IOSDIAG_BPF(iosdiag_virtblk, 1))
			return -1;
	} else if (!strcmp(module_name, "nvme")) {
		if (LOAD_IOSDIAG_BPF(iosdiag_nvme, 1))
			return -1;
	} else if (!strcmp(module_name, "scsi")) {
		if (LOAD_IOSDIAG_BPF(iosdiag_scsi, 1))
			return -1;
	} else {
		if (LOAD_IOSDIAG_BPF(iosdiag_virtblk, 1)) {
			if (LOAD_IOSDIAG_BPF(iosdiag_nvme, 1)) {
				if (LOAD_IOSDIAG_BPF(iosdiag_scsi, 1))
					return -1;
			} else {
				LOAD_IOSDIAG_BPF(iosdiag_scsi, 0);
			}
		} else {
			LOAD_IOSDIAG_BPF(iosdiag_nvme, 0);
			LOAD_IOSDIAG_BPF(iosdiag_scsi, 0);
		}
	}
	if (iosdiag_virtblk_bpf_load)
		iosdiag_virtblk_map =
			bpf_map__fd(iosdiag_virtblk->maps.iosdiag_virtblk_maps);
	if (target_devt)
		bpf_map_update_elem(iosdiag_maps_targetdevt, &key, &target_devt, BPF_ANY);
	return 0;
}

int iosdiag_run(int timeout, char *output_file)
{
	int fd_log;
	char filepath[256];
	char cmd[272];

	if (strlen(output_file) > (sizeof(filepath) - 1)) {
		printf("error: output file name(%s) too large(max %lu bytes)\n",
			output_file, sizeof(filepath));
		return -1;
	}
	strcpy(filepath, output_file);
	sprintf(cmd, "mkdir %s -p", dirname(filepath));
	exec_shell_cmd(cmd);
	fd_log = open(output_file, O_RDWR | O_CREAT, 0755);
	if (fd_log < 0) {
		printf("error: create output file \"%s\" fail\n", output_file);
		return -1;
	}
	signal(SIGINT, iosdiag_stop);
	signal(SIGALRM, iosdiag_stop);
	if (timeout)
		alarm(timeout);
	iosdiag_store_result(fd_log);
	close(fd_log);
	return 0;
}

void iosdiag_exit(char *module_name)
{
	if (iosdiag_virtblk_bpf_load)
		iosdiag_virtblk_bpf__destroy(iosdiag_virtblk);
	if (iosdiag_nvme_bpf_load)
		iosdiag_nvme_bpf__destroy(iosdiag_nvme);
	if (iosdiag_scsi_bpf_load)
		iosdiag_scsi_bpf__destroy(iosdiag_scsi);
}
