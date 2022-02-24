#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include "parser.h"

#define OPT_MASK 0x7
#define	OPT_IRQ	0x1	
#define	OPT_SCH	0x2
#define	OPT_LAT	0x4
#define MAX_CMD 3
#define MAX_CMD_LEN 128

char *firq = "/proc/sysak/runlatency/irqoff/enable";
char *fsch = "/proc/sysak/runlatency/nosch/enable";
char *flat = "/proc/sysak/runlatency/runqlat/pid";

static void usage(char *prog)
{
	const char *str =
	"  Usage: %s [OPTIONS]\n"
	"  Options:\n"
	"  -f              the output file\n"
	"  -r              read the result to file or stdio\n"
	"  -d              disable the monitor, 7-all, 1-irq, 2-nosched, 4-runlat\n"
	"  -e              enable the monitor, 7-all, 1-irq, 2-nosched, 4-runlat\n"
	"\n";

	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

char *cmdstr[3];

int switch_func(int opt, int enable, int arg)
{
	FILE *fp;
	int param[3], ret, index = 0;
	int optalign;
	char cmd[MAX_CMD_LEN] = {0};
	

	optalign = opt & OPT_MASK;

	if (optalign & OPT_LAT)
		param[2] = arg;
	else
		param[2] = enable;

	param[0] = param[1] = enable;
	while (index < MAX_CMD) {	
		if (optalign & (1 << index)) {
			snprintf(cmd, MAX_CMD_LEN, "echo %d > %s",param[index], cmdstr[index]);
			/* fprintf(stderr, "debug_cmd:%s\n", cmd); */
			fp = popen(cmd, "r");
			if (!fp) {
				ret = errno;
				perror(cmd);
				return ret;
			}
			optalign = optalign;
			index++;
		}
	}
}

int main(int argc, char *argv[])
{
	char *refile = NULL;
	int pid = -1, ret = 0, i, will_switch, enable;
	int c, option_index, en_opt, dis_opt;

	opterr = 0;
	dis_opt = en_opt = OPT_MASK;

	cmdstr[0] = firq;
	cmdstr[1] = fsch;
	cmdstr[2] = flat;
	for (i = 0; i < MAX_CMD; i++) {
		if (access(cmdstr[i], F_OK)) {
			ret = errno;
			fprintf(stderr, "%s:access() %s\n",
				strerror(errno), cmdstr[i]);
			return ret;
		}
	}
	for (;;) {
		c = getopt_long(argc, argv, "f:p:e::d::hr",
				NULL /*long_options*/, &option_index);

		if (c == -1)
			break;
		switch (c) {
			case 'f':
				refile = optarg;
				break;
			case 'r':
				pasre_dump(refile);//do something
				break;
			case 'p':
				pid = atoi(optarg);
				fprintf(stderr, "debug_p_pid=%d\n", pid);
				break;
			case 'e':
				if (optarg)
					en_opt = atoi(optarg);
				fprintf(stderr, "debug_e_pid=%d\n", pid);
				will_switch = 1;
				enable = 1;
				break;
			case 'd':
				if (optarg)
					dis_opt = atoi(optarg);
				will_switch = 1;
				enable = 0;
				break;
			case 'h':
				usage(argv[0]);
				break;
			default:
				usage(argv[0]);
		}
	}
	if (will_switch)
		ret = switch_func(dis_opt, enable, pid);

	return ret;
}
