#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "parser.h"

#define IRQOFF_FILE  "/proc/runlatency/irqoff/latency"
#define NOSCH_FILE   "/proc/runlatency/nosch/stack_trace"
#define RUNQ_FILE	 "/proc/runlatency/runqlat/runqlat"

#define STREAM_SIZE	(128 * 1024)

int read_file(char* path, char* s)
{
	int fd = open(path, O_RDONLY);
	int size;
	
	if (fd < 0) {
		return fd;
	}
	
	size = read(fd, s, STREAM_SIZE - 1);
	close(fd);
	return size;
}

int clear_file(char *path)
{
	int fd = open(path, O_WRONLY);
	int size;
	
	if (fd < 0) {
		return fd;
	}
	
	size = write(fd, "0", 1);
	close(fd);
	return size;
}

int main(void)
{
	char *s;
	int ret;
	
	s = malloc(STREAM_SIZE);
	if (s == NULL) {
		return -ENOMEM;
	}
	
	ret = read_file(IRQOFF_FILE, s);
	if (ret < 0) {
		goto failed;
	}
	s[ret] = '\0';
	parser_irqoff(s, ret);
	
	ret = read_file(NOSCH_FILE, s);
	if (ret < 0) {
		goto failed;
	}
	s[ret] = '\0';
	parser_nosch(s, ret);
	clear_file(NOSCH_FILE);
	
	ret = read_file(RUNQ_FILE, s);
	if (ret < 0) {
		goto failed;
	}
	s[ret] = '\0';
	parser_runq(s, ret);
	clear_file(RUNQ_FILE);
	
	free(s);
	return 0;
	
failed:
	free(s);
	return ret;
}
