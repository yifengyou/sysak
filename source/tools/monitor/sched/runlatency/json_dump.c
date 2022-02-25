#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "parser.h"

#define IRQOFF_FILE  "/proc/sysak/runlatency/irqoff/latency"
#define NOSCH_FILE   "/proc/sysak/runlatency/nosch/stack_trace"
#define RUNQ_FILE	 "/proc/sysak/runlatency/runqlat/runqlat"

#define STREAM_SIZE	(128 * 1024)

int read_file(char* path, char* s)
{
	int fd = open(path, O_RDONLY);
	int size;
	
	if (fd < 0) {
		fprintf(stderr, "%s :open %s\n",
			strerror(errno), path);
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
		fprintf(stderr, "%s :open %s\n",
			strerror(errno), path);
		return fd;
	}
	
	size = write(fd, "0", 1);
	close(fd);
	return size;
}

int parse_dump(char *file)
{
	char *s;
	int ret;
	FILE *outf = NULL;
	
	s = malloc(STREAM_SIZE);
	if (s == NULL) {
		return -ENOMEM;
	}

	if (file) {
		outf = fopen(file, "a+");
		if (!outf) {
			ret = errno;
			fprintf(stderr, "%s :fopen %s\n",
				strerror(errno), file);
			goto failed;
		}
	} else {
		goto failed;
	}
	ret = read_file(IRQOFF_FILE, s);
	if (ret < 0) {
		goto failed;
	}
	s[ret] = '\0';
	parser_irqoff(s, ret, outf);
	
	ret = read_file(NOSCH_FILE, s);
	if (ret < 0) {
		goto failed;
	}
	s[ret] = '\0';
	parser_nosch(s, ret, outf);
	clear_file(NOSCH_FILE);
	
	ret = read_file(RUNQ_FILE, s);
	if (ret < 0) {
		goto failed;
	}
	s[ret] = '\0';
	parser_runq(s, ret, outf);
	clear_file(RUNQ_FILE);
	
	free(s);
	if (outf)
		fclose(outf);
	return 0;
	
failed:
	free(s);
	if (outf)
		fclose(outf);
	return ret;
}
