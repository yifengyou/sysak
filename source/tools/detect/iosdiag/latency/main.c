#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <fcntl.h>
#include "iosdiag.h"

static void usage(void)
{
	fprintf(stdout,
		"\nUsage: \n"
		"latency [OPTION] disk_devname       Detect IO latency in specified disk\n"
		"latency -t ms disk_devname          Set IO latency threshold(default 1000ms)\n"
		"latency -T sec disk_devname         How long to detect IO latency(default 10s)\n"
		"latency -f log disk_devname         Specify the output file log\n"
		"\ne.g.\n"
		"latency vda                         Detect IO latency in disk \"vda\"\n"
		"latency -t 10 vda                   Set IO latency threshold 10ms and detect IO latency in disk \"vda\"\n"
		"latency -t 10 -T 30 vda             Detect IO latency in disk \"vda\" 30 secs\n");
	exit(-1);
}

static unsigned long g_threshold_us;
unsigned long get_threshold_us(void)
{
	return g_threshold_us;
}

int main(int argc, char *argv[])
{
	int ch;
	int timeout_s = 10, threshold_ms = 1000;
	char *result_file = "/var/log/sysak/iosdiag/latency/result.log";
	char *devname;

	while ((ch = getopt(argc, argv, "T:t:f:h")) != -1) {
		switch (ch) {
			case 'T':
				timeout_s = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 't':
				threshold_ms = (int)strtoul(optarg, NULL, 0);
				break;
			case 'f':
				result_file = optarg;
				break;
			case 'h':
			default:
				usage();
		}
	}
	devname = argv[argc - 1];
	g_threshold_us = threshold_ms * 1000;
	if (iosdiag_init(devname)) {
		fprintf(stderr, "iosdiag_init fail\n");
		return -1;
	}
	iosdiag_run(timeout_s, result_file);
	iosdiag_exit(devname);
	return 0;
}

