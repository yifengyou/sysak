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
#include "iosdiag.h"
#include "base_info.h"
#include "json_format.h"

#define JSON_BUFFER_SIZE	(512*1024)

struct repeat_io {
	unsigned long io_start;
	unsigned long sector;
};

static struct repeat_io g_repeat_io[MAX_STORE_RQ_CNT];
static int g_stop;
static int g_threshold = 5000; //5000ms
static int g_timeout = 10; //10s
static struct rq_hang_info *g_rq_hi;
static char *g_json_buf;
static int g_fd_res = -1;
static int g_fd_rq_hang_detect = -1;
static int g_bio_file_info;
static int g_once_capture_exit;
static char *g_result_dir = "/var/log/sysak/iosdiag/hangdetect";
static char g_check_time_date[24];

static void detect_stop(int signo)
{
	printf("hang detect stop!\n");
	g_stop = 1;
}

static void set_timeout_exit(void)
{
	signal(SIGINT, detect_stop);
	signal(SIGALRM, detect_stop);
	if (g_timeout)
		alarm(g_timeout);
}

static int exec_shell_cmd(char *cmd)
{
	char buf[128];
	FILE *fp;

	if (!cmd)
		return -1;

	if ((fp = popen(cmd, "r")) == NULL) {
		fprintf(stderr, "exec \'%s\' fail\n", cmd);
		return -1;
	}

	buf[sizeof(buf) - 1] = '\n';
	while (fgets(buf, sizeof(buf) - 1, fp))
		fprintf(stdout, "%s", buf);
	pclose(fp);
	return 0;
}

static void set_check_time_date(void)
{
	struct timeval tv;
	struct tm *p;

	gettimeofday(&tv, NULL);
	p = localtime(&tv.tv_sec);
	sprintf(g_check_time_date, "%d-%d-%d %d:%d:%d.%ld", 
		    1900+p->tm_year,
			1+p->tm_mon,
			p->tm_mday,
			p->tm_hour,
			p->tm_min,
			p->tm_sec,
			tv.tv_usec / 1000);
	set_base_info_check_time_date(g_check_time_date);
}

static int trigger_rq_hang_collect(int fd, char *devname, int major, int minor,
	int threshold)
{
	char devinfo[32] = {0};

	if (major < 1 || minor < 0) {
		fprintf(stderr, "invalid devnum(%d, %d)\n", major, minor);
		return -1;
	}

	sprintf(devinfo, "%s:%d:%d %d %d", devname, major, minor, threshold, g_bio_file_info);
	set_check_time_date();
	if (write(fd, devinfo, strlen(devinfo) + 1) != (strlen(devinfo) + 1)) {
		fprintf(stderr, "write devinfo \'%s\' fail(%s)\n", devinfo, strerror(errno));
		return -1;
	}
	return 0;
}

static struct rq_hang_info *get_rq_hang_info_buffer(void)
{
	int fd;
	void *p;
	char *path = "/proc/disk_hang/rq_hang_detect";

	fd = open(path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open \'%s\' fail(%s)\n"
				"Please confirm the driver module is loaded\n",
				path, strerror(errno));
		return NULL;
	}

	p = mmap(NULL, (sizeof(struct rq_hang_info) * MAX_STORE_RQ_CNT),
		 PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap \'%s\' fail(%s)\n", path, strerror(errno));
		close(fd);
		return NULL;
	}
	g_fd_rq_hang_detect = fd;

	return (struct rq_hang_info *)(p);
}

static void put_rq_hang_info_buffer(struct rq_hang_info *buf)
{
	void *p;

	if (!buf)
		return;
	p = (void *)buf;
	munmap(p, sizeof(struct rq_hang_info) * MAX_STORE_RQ_CNT);
	if (g_fd_rq_hang_detect != -1)
		close(g_fd_rq_hang_detect);
}

static int open_result_file(char *filename)
{
	int fd;
	char buf[256];
	char cmd[272];

	if (strlen(filename) > (sizeof(buf) - 1)) {
		printf("error: output file name(%s) too large(max %d bytes)\n",
			filename, sizeof(buf));
		return -1;
	}
	strcpy(buf, filename);
	sprintf(cmd, "mkdir %s -p", dirname(buf));
	exec_shell_cmd(cmd);
	fd = open(filename, O_RDWR | O_CREAT, 0755);
	if (fd < 0) {
		printf("error: create output file \"%s\" fail\n", filename);
		return -1;
	}
	return fd;
}

static void write_result_file(int fd, char *buf, unsigned int len)
{
	write(fd, buf, len);
}

static void close_result_file(int fd)
{
	if (fd > 0)
		close(fd);
}

static void usage(void)
{
	fprintf(stdout,
		"\nUsage: \n"
		"hangdetect [OPTION] disk_devname       Detect IO hang in specified disk\n"
		"hangdetect -t ms disk_devname          Set IO hang threshold(default 5000ms)\n"
		"hangdetect -T sec disk_devname         How long to detect IO hang(default always)\n"
		"hangdetect -f log disk_devname         Specify the output file log\n"
		"hangdetect -o disk_devname             Auto exit once capture some ios\n"
		"\ne.g.\n"
		"hangdetect vda                         Detect IO hang in disk \"vda\"\n"
		"hangdetect -t 1000 vda                 Set IO hang threshold 1000ms and detect IO hang in disk \"vda\"\n"
		"hangdetect -t 1000 -o vda              Detect IO hang delay for 1000ms in disk \"vda\" and auto exit once capture some ios\n"
		"hangdetect -T 10 vda                   Detect IO hang in disk \"vda\" 10 secs\n");
	exit(-1);
}

static int rq_existed_result_file(struct rq_hang_info *rq_hi, int idx)
{
	int existed = 0;
	static unsigned int major = 0;
	static unsigned int minor = 0;

	if (g_repeat_io[idx].io_start == rq_hi->io_start_ns &&
	    g_repeat_io[idx].sector == rq_hi->sector &&
	    major == get_bdi_major() &&
	    minor == get_bdi_minor())
	    existed = 1;

	g_repeat_io[idx].io_start = rq_hi->io_start_ns;
	g_repeat_io[idx].sector = rq_hi->sector;
	major = get_bdi_major();
	minor = get_bdi_minor();
	return existed;
}

static void paser_arg(int argc, char *argv[])
{
	int ch;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "T:t:f:heo")) != -1) {
		switch (ch) {
			case 'T':
				g_timeout = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 't':
				g_threshold = (int)strtoul(optarg, NULL, 0);
				break;
			case 'f':
				g_result_dir = optarg;
				break;
			case 'e':
				g_bio_file_info = 1;
				break;
			case 'o':
				g_once_capture_exit = 1;
				break;
			case 'h':
			default:
				usage();
		}
	}
}

static int run_collect(void)
{
	struct rq_hang_info *rq_hi = g_rq_hi;
	char *json_buf = g_json_buf;
	int fd_res = g_fd_res;
	int current_bdi_idx = 0, muti_disk_collet = 0, capture_io = 0;
	int i;

	if (get_current_bdi_idx() < 0) {
		//check muti disk
		set_current_bdi_idx(current_bdi_idx);
		muti_disk_collet = 1;
	}

	do {
		if (!trigger_rq_hang_collect(g_fd_rq_hang_detect,
					    get_bdi_diskname(),
					    get_bdi_major(),
					    get_bdi_minor(),
					    g_threshold)) {
			for (i = 0; i < MAX_STORE_RQ_CNT; i++) {
				if (!rq_hi[i].req_addr)
					continue;
				if (rq_existed_result_file(&rq_hi[i], i))
					continue;
				set_base_info_file(NULL);
				convert_to_json(json_buf, &rq_hi[i]);
				write_result_file(fd_res, json_buf, strlen(json_buf));
				capture_io = 1;
				//printf(json_buf);
			}
		} else {
			fprintf(stderr, "trigger \'%s\' rq_hang collect fail\n",
				get_bdi_diskname());
			return -1;
		}
		current_bdi_idx++;
	} while (muti_disk_collet && !set_current_bdi_idx(current_bdi_idx));

	if (capture_io && g_once_capture_exit)
		return 1;

	if (muti_disk_collet)
		set_current_bdi_idx(-1);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	char resultfile_path[256];

	paser_arg(argc, argv);
	g_rq_hi = get_rq_hang_info_buffer();
	if (!g_rq_hi) {
		fprintf(stderr, "get rq hang buffer fail\n");
		usage();
	}

	g_json_buf = malloc(JSON_BUFFER_SIZE);
	if (!g_json_buf) {
		fprintf(stderr, "malloc json_buf fail\n");
		ret = -1;
		goto put_rq_buf;
	}
	memset(g_json_buf, 0x0, JSON_BUFFER_SIZE);

	sprintf(resultfile_path, "%s/result.log.seq", g_result_dir);
	g_fd_res = open_result_file(resultfile_path);
	if (g_fd_res < 0) {
		fprintf(stderr, "create result file fail\n");
		ret = -1;
		goto free_json_buf;
	}
	if (!base_info_init(argv[argc - 1])) {
		set_timeout_exit();
		while (!g_stop) {
			if (run_collect())
				break;
			usleep(g_threshold / 2 * 1000);
		}
	}
	base_info_exit();
close_file:
	close_result_file(g_fd_res);
free_json_buf:
	free(g_json_buf);
put_rq_buf:
	put_rq_hang_info_buffer(g_rq_hi);
	return ret;
}

