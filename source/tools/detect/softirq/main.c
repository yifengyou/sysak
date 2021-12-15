#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_PATH_LEN 200
#define PROC_SOFTIRQ "/proc/softirqs"
#define MAX_LINE_LEN 4096

static char g_softirq_file[MAX_PATH_LEN] = {0};
static char g_res_file[MAX_PATH_LEN] = {0};
static FILE *g_softirq_fp;
static FILE *g_res_fp;
static bool g_calc_res = false;

static void usage(void)
{
    fprintf(stdout,
			"sysak softirq: calculate softirq speed.It is used by tool loadtask.If you want use,please follow the steps below:\n"
			"         1.run command 'softirq -s sourcefile' to output initial value to sourcefile\n"
			"         2.sleep one second\n"
			"         3.run command 'softirq -s sourcefile -r resultfile' to output result to resultfile\n"
			"options: -h, help information\n"
            "         -s sourcefile, output initial value to sourcefile or get intial value from sourcefile\n"
			"         -r resultfile, output result to resultfile\n");
    exit(-1);
}

static void parse_arg(int argc, char *argv[])
{
	int ch;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "s:r:h")) != -1) {
		switch (ch) {
			case 's':
				if (optarg && (strlen(optarg) < MAX_PATH_LEN))
					strncpy(g_softirq_file, optarg, strlen(optarg));
				else
					exit(-1);
				break;
			case 'r':
				g_calc_res = true;
				if (optarg && (strlen(optarg) < MAX_PATH_LEN))
					strncpy(g_res_file, optarg, strlen(optarg));
				else
					exit(-1);
				break;
			case 'h':
			default:
				usage();
				break;
		}
	}

	if (!g_softirq_file[0])
		exit(-1);
}

int calc_softirq(void)
{
	char line[MAX_LINE_LEN] = {0};
	char *str;
	char sum_str[30] = {0};
	bool flag = false;
	int ret = 0;
	long long sum = 0;
	FILE *fp = fopen(PROC_SOFTIRQ, "r");

	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		if (!flag) {
			flag = true;
			continue;
		}

		str = strtok(line, " ");
		if (!str) {
			ret = -1;
			break;
		}

		if (fwrite(str, strlen(str), 1, g_softirq_fp) != 1) {
			ret = -1;
			break;
		}
		
		sum = 0;
		while (str = strtok(NULL,  " \n")) {
			sum += atoll(str);
		}

		snprintf(sum_str, sizeof(sum_str), "%lld\n", sum);
		if (fwrite(sum_str, strlen(sum_str), 1, g_softirq_fp) != 1) {
			ret = -1;
			break;
		}
	}

	fclose(fp);
	return ret;
}

int calc_softirq_speed(void)
{
	char line[MAX_LINE_LEN] = {0};
	char res_line[50] = {0};
	bool flag = false;
	int ret = 0;
	long long end_sum = 0;
	long long start_sum = 0;
	long long diff = 0;
	char *str;
	char *space_str = "      ";
	FILE *fp = fopen(PROC_SOFTIRQ, "r");

	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		if (!flag) {
			flag = true;
			continue;
		}

		str = strtok(line, " ");
		if (!str) {
			ret = -1;
			break;
		}

		if (fwrite(space_str, strlen(space_str), 1, g_res_fp) != 1) {
			ret = -1;
			break;
		}

		if (fwrite(str, strlen(str), 1, g_res_fp) != 1) {
			ret = -1;
			break;
		}

		end_sum = 0;
		while (str = strtok(NULL,  " \n")) {
			end_sum += atoll(str);
		}

		if (!fgets(res_line, sizeof(res_line), g_softirq_fp)) {
			ret = -1;
			break;
		}

		str = strtok(res_line, ":");
		if (!str) {
			ret = -1;
			break;
		}

		str = strtok(NULL,  "\n");
		if (!str) {
			ret = -1;
			break;
		}

		start_sum = atoll(str);
		diff = end_sum - start_sum;
		
		snprintf(res_line, sizeof(res_line), "%lld counts/s\n", diff);
		if (fwrite(res_line, strlen(res_line), 1, g_res_fp) != 1) {
			ret = -1;
			break;
		}
	}

	fclose(fp);
	return ret;
}

int main(int argc, char *argv[])
{
	parse_arg(argc, argv);


	if (!g_calc_res) {
		g_softirq_fp = fopen(g_softirq_file, "w+");
		if (!g_softirq_fp)
			exit(-1);

		calc_softirq();
	}
	else {
		g_softirq_fp = fopen(g_softirq_file, "r");
		if (!g_softirq_fp)
			exit(-1);

		g_res_fp = fopen(g_res_file, "w+");
		if (!g_res_fp) {
			fclose(g_softirq_fp);
			exit(-1);
		}

		calc_softirq_speed();

		fclose(g_res_fp);
	}

	fclose(g_softirq_fp);
	return 0;	
}
