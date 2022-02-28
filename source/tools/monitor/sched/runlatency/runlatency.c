#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include "parser.h"

#define OPT_MASK 0x7
#define	OPT_IRQ	0x1	
#define	OPT_SCH	0x2
#define	OPT_LAT	0x4
#define MAX_CMD 3
#define MAX_CMD_LEN 128

bool ready[MAX_CMD] = {false};
int retno[MAX_CMD] = {0};
char *enable_files[] = {"/proc/sysak/runlatency/irqoff/enable",
		    "/proc/sysak/runlatency/nosch/enable",
		    "/proc/sysak/runlatency/runqlat/pid"};
char *trsh_files[] = {"/proc/sysak/runlatency/irqoff/latency",
		    "/proc/sysak/runlatency/nosch/threshold",
		    "/proc/sysak/runlatency/runqlat/threshold"};

static void usage(char *prog)
{
	const char *str =
	"  Usage: %s -e [-p pid], [-t t1 t2 t3]\n"
	"  Options:\n"
	"  -p        <pid> set the pid we monitor, used with -e or separately\n"
	"  -t        <thresh1 thresh2 thresh3> set thresh:latirq=thresh1, nosched=thresh2, runq=thresh3 \n"
	"  -r        [outfile] read result to outfile, if not point,to stdout\n"
	"  -d        [mask] disable the monitor, 7-all, 1-irq, 2-nosched, 4-runlat, default=7\n"
	"  -e        [mask]enable the monitor, 7-all, 1-irq, 2-nosched, 4-runlat, default=7\n"
	"for example:\n"
	"  sysak runlatency -e -p 78953  #enable all runaltency monitor for task 78953\n"
	"  sleep 20                       #Sampling for 20 seconds 20\n"
	"  sysak runlatency -r ./my.json  #record the sampling result to my.json\n"
	"  sysak runlatency -d            #close all runaltency monitor\n"
	;

	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

int switch_func(int opt, int enable, int pid)
{
	FILE *fp;
	int param[3], ret, index = 0;
	int optalign;
	char cmd[MAX_CMD_LEN] = {0};

	optalign = opt & OPT_MASK;

	if (optalign & OPT_LAT)
		param[2] = (enable != 0) ? pid:-1;

	param[0] = param[1] = enable;
	while (index < MAX_CMD) {	
		if (optalign & (1 << index)) {
			snprintf(cmd, MAX_CMD_LEN, "echo %d > %s",param[index], enable_files[index]);
			/* fprintf(stderr, "debug_cmd:%s\n", cmd); */
			fp = popen(cmd, "r");
			if (!fp) {
				ret = errno;
				perror(cmd);
				return ret;
			}
		}
		index++;
	}

	return 0;
}

int set_thresh(unsigned long *thresh)
{
	FILE *fp;
	int i = 0, ret;
	char cmd[MAX_CMD_LEN] = {0};

	for (; i < MAX_CMD; i++) {
		snprintf(cmd, MAX_CMD_LEN, "echo %llu > %s",
				thresh[i]*1000*1000, trsh_files[i]);
		fp = popen(cmd, "r");
		if (!fp) {
			ret = errno;
			perror(cmd);
			return ret;
		}
	}
	return 0;
}

static int all_ready(bool ready[], int retno[])
{
	int i, ready_cnt = 0;

	for (i = 0; i < MAX_CMD; i++) {
		if (ready[i]) {
			ready_cnt++;
		} else {
			fprintf(stderr, "%s: access() %s\n",
				strerror(retno[i]), enable_files[i]);	
		}
	}

	return (ready_cnt == MAX_CMD);
}

int main(int argc, char *argv[])
{
	char *refile = NULL;
	int pid = -1, ret = 0, i, will_switch = 0, enable = -1;
	int c, option_index, opt_mask;
	bool will_thresh = false;
	unsigned long thresh[MAX_CMD] = {0};

	opterr = 0;
	opt_mask = 0;

	for (i = 0; i < MAX_CMD; i++) {
		if (access(enable_files[i], F_OK)) {
			retno[i] = errno;
			ready[i] = false;
		} else {
			retno[i] = 0;
			ready[i] = true;
		}
	}
	for (;;) {
		c = getopt_long(argc, argv, "p:e::d::trh",
				NULL /*long_options*/, &option_index);

		if (c == -1)
			break;
		switch (c) {
			case 'r':
				if (!all_ready(ready, retno))
					return -1;
				if (argc > optind)	/* for -r xxx.log */
					refile = argv[optind];
				parse_dump(refile);//do something
				break;
			case 't':
				if (!all_ready(ready, retno))
					return -1;
				if (argc > optind + 2)	{ /* -t follows 3 arguments */
					for (i = 0; i < MAX_CMD; i++) {
						if (isdigits(argv[i+optind]))
							thresh[i] = strtoul(argv[i+optind], NULL, 10);
						else
							break;
					}
					if (i >= MAX_CMD)
						will_thresh = true;
					else
						printf("-t must follows 3 digitals\n");
				} else {
					printf("\"-t\" must follows 3 digitals\n");
					usage("sysak runlatency");
				}
				break;
			case 'p':
				pid = atoi(optarg);
				will_switch = 1;
				opt_mask |= OPT_LAT;
				break;
			case 'e':
				if (!all_ready(ready, retno))
					return -1;
				if (optarg)
					opt_mask = atoi(optarg);
				else
					opt_mask = OPT_MASK & (~OPT_LAT);
					
				will_switch = 1;
				enable = 1;
				break;
			case 'd':
				if (!all_ready(ready, retno))
					return -1;
				if (optarg)
					opt_mask = atoi(optarg);
				else
					opt_mask = OPT_MASK;
				will_switch = 1;
				enable = 0;
				break;
			case 'h':
				usage("sysak runlatency");
				break;
			default:
				usage("sysak runlatency");
		}
	}
	if (will_switch)
		ret = switch_func(opt_mask, enable, pid);
	if (ret)
		return ret;
	if (will_thresh)
		ret = set_thresh(thresh);
	return ret;
}
