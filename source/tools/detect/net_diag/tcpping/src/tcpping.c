/*
 * Author: Chen Tao
 * Create: Mon Jan 17 14:12:28 2022
 */
#define _GNU_SOURCE
#include <libnet.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpping.skel.h"
#include "data_define.h"
#include <sys/time.h>
#include <sys/resource.h>
#include "cJSON.h"

//#define DEBUG
#define BTF_PATH_MAX 128
char btf_path_buf[BTF_PATH_MAX] = "/tmp/vmlinux-";
bool exiting = false;
libnet_t *handle; /* Libnet句柄 */
char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */

struct trace_path {
	char *path;
	int to;
	int from;
};

static const struct trace_path trace_path[] = {
	{"t_trans", PT_KERN_RAW_SENDMSG, PT_USER},
	{"t_ip", PT_KERN_DEV_QUE_XMIT, PT_KERN_RAW_SENDMSG},
	{"r_remote", PT_KERN_NET_RECV_SKB, PT_KERN_DEV_QUE_XMIT},
	{"r_dev", PT_KERN_IP_RCV, PT_KERN_NET_RECV_SKB},
	{"r_ip", PT_KERN_TCP_V4_RCV, PT_KERN_IP_RCV},
	{"delta", PT_KERN_TCP_V4_RCV, PT_USER},
};

struct trace_para {
	struct tuple_info tuple;
	int pack_nr; /* package count */
	int delay; /* delay send ms*/
	int output_mode;  /*0:print, 1:json */
	FILE *file;
	cJSON *root;
	int cpu;
};

struct trace_para trace_para = {
	.tuple = {
		.src_ip = 0,
		.dst_ip = 0,
		.src_port = 30330,
		.dst_port = 80,
	},
	.pack_nr = 100,
	.delay = 1, /* 1ms */
	.output_mode = 0,
	.file = NULL,
	.root = NULL,
	.cpu = 0,
};

struct raw_times {
	__u64 times[10];
};

struct trace_time {
	struct raw_times *time;
	int time_id;
	int out_id;
	int in_id;
	int size;
};

struct trace_time trace_time = {
	.time = NULL,
	.time_id = 0,
	.out_id = 0,
	.in_id = 0,
	.size = 0,
};

struct tuple_info tuple = {
	.src_ip = 0,
	.dst_ip = 0,
	.src_port = 0,
	.dst_port = 0,
};

struct data {
	__u32 t_trans;
	__u32 t_ip;
	__u32 t_dev;
	__u32 r_remote;
	__u32 r_dev;
	__u32 r_ip;
	__u32 delta;
};

struct data data_min = {0};
struct data data_avg = {0};
struct data data_max = {0};
struct data image = {0};

#define DATA_MIN(path)    data_min.path = data_min.path < image.path ? data_min.path : image.path;
#define DATA_MAX(path)    data_max.path = data_max.path > image.path ? data_max.path : image.path;
#define DATA_AVG(path)    data_avg.path = data_avg.path + image.path;
#define DELTA(path, to, from)  image.path = (time[nr].times[to] - time[nr].times[from]) / 1000; 

//static char path[5] = {'v', '>', '^', 'v', '<'};

static void json_dump(int nr)
{
	int i;
	cJSON *root;
	char *out;
	cJSON *next;

	root = trace_para.root;
	next = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "data", next);
	cJSON_AddNumberToObject(next, "seq", nr);
	for (i = 0; i < sizeof(trace_path) / sizeof(struct trace_path); i++) {
		cJSON_AddNumberToObject(next, trace_path[i].path,
				(trace_time.time[nr].times[trace_path[i].to] -
				trace_time.time[nr].times[trace_path[i].from]) / 1000);
	}
	if (nr == trace_para.pack_nr - 1) {
		out = cJSON_Print(root);
		if (trace_para.file) {
			fprintf(trace_para.file, "%s\n", out);
		}
		free(out);
	}
}

static int trace_output_init(char *path)
{

	trace_para.file = fopen(path, "w+");
	if (!trace_para.file) {
		printf("output path is wrong:%s\n", path);
		return -1;
	}
	trace_para.root = cJSON_CreateObject();
	if (!trace_para.root) {
		printf("create json root failed\n");
		return -1;
	}

	return 0;
}

static void trace_output_close(void)
{
	if (trace_para.file)
		fclose(trace_para.file);
	if (trace_para.root)
		cJSON_Delete(trace_para.root);
}

/*
static char move_path(int local, int nr)
{
	if (nr % 5 == local) {
		return path[local];
	} else if (local == 0 || local == 2 || local == 0) {
		return '|';
	} else {
		return '-';
	}
}
*/

static void image_show(int nr)
{
	struct raw_times *time = NULL;
	struct in_addr dip = {
		.s_addr = trace_para.tuple.dst_ip,
	};

	time = trace_time.time;
	DELTA(t_trans, PT_KERN_RAW_SENDMSG, PT_USER)
	DELTA(t_ip, PT_KERN_DEV_QUE_XMIT, PT_KERN_RAW_SENDMSG)
	DELTA(r_remote, PT_KERN_NET_RECV_SKB, PT_KERN_DEV_QUE_XMIT)
	DELTA(r_dev, PT_KERN_IP_RCV, PT_KERN_NET_RECV_SKB)
	DELTA(r_ip, PT_KERN_TCP_V4_RCV, PT_KERN_IP_RCV)
	DELTA(delta, PT_KERN_TCP_V4_RCV, PT_USER)

	DATA_MIN(t_trans)
	DATA_MIN(t_ip)
	DATA_MIN(r_remote)
	DATA_MIN(r_dev)
	DATA_MIN(r_ip)
	DATA_MIN(delta)

	DATA_MAX(t_trans)
	DATA_MAX(t_ip)
	DATA_MAX(r_remote)
	DATA_MAX(r_dev)
	DATA_MAX(r_ip)
	DATA_MAX(delta)

	DATA_AVG(t_trans)
	DATA_AVG(t_ip)
	DATA_AVG(r_remote)
	DATA_AVG(r_dev)
	DATA_AVG(r_ip)
	DATA_AVG(delta)
	
	printf("+-------------------tcp-trace---------------------+\n");
	printf("| seq:%5d                       unit:usec       |\n", nr);
	printf("|      +-------+      %5u  +---------------+    |\n", image.delta);
	printf("|      | local |  ---------> |   %12s|    |\n", inet_ntoa(dip));
	printf("|      +-------+             +---------------+    |\n");
	printf("|        |    user    |                           |\n");
	printf("|  ------------------------         +--------+    |\n");
	printf("|        |            |             |        |    |\n");
	printf("|  %5u | trans layer|             |        |    |\n", image.t_trans);
	printf("|  ------------------------         |        |    |\n");
	printf("|        |            |             |        |    |\n");
	printf("|  %5u |  ip layer  | %5u       |        |    |\n", image.t_ip, image.r_ip);
	printf("|        |-----------------         |        ^    |\n");
	printf("|        |            |             v        |    |\n");
	printf("|        |  dev layer | %5u       |        |    |\n", image.r_dev);
	printf("|  ------|------------|----         |        |    |\n");
	printf("|        v            |   %5u     |        |    |\n", image.r_remote);
	printf("|        |            +-------<-----+        |    |\n");
	printf("|        +---------------->------------------+    |\n");
	printf("|                                                 |\n");
	printf("+-------------------------------------------------+\n");
}

static void record_start_time(int nr)
{
	struct timespec ts = {0};
	__u64 curr;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	curr = ts.tv_sec * 1000000000 + ts.tv_nsec;
	if (!trace_time.time) {
		trace_time.time = (struct raw_times *)calloc(nr, sizeof(struct raw_times));
		trace_time.size = nr;
	}
	trace_time.time[trace_time.time_id++].times[PT_USER] = curr;
}

static int probe(int nr, __u32 src_ip, __u32 dst_ip, __u16 src_port,
		 __u16 dst_port)
{
 	int packet_size; /* 构造的数据包大小 */
	libnet_ptag_t ip_tag, tcp_tag, data_tag; /* 各层build函数返回值 */
	u_short proto = IPPROTO_TCP; /* 传输层协议 */
	u_char payload[64] = {0}; /* 承载数据的数组，初值为空 */
	u_long payload_s = 0; /* 承载数据的长度，初值为0 */
	int i;
	int seq = 0;
	int ret;

	/*
	// 初始化Libnet
	if ((handle = libnet_init(LIBNET_RAW4, NULL, error)) == NULL) {
		printf("libnet_init failure:%s\n", error);
		return -1;
	}
	*/
	strncpy((char *)payload, "test", sizeof(payload)-1); /* 构造负载的内容 */
	payload_s = strlen((char *)payload); /* 计算负载内容的长度 */
	packet_size = LIBNET_IPV4_H + LIBNET_TCP_H + payload_s;	
	for (i = 0; i < nr; i++) {
		//payload_s = 0;
		//data_tag = libnet_build_data(payload, payload_s, handle, 0);
		data_tag = 0;
		//printf("data_tag:%d, libnet_tcp:%d\n", (int)data_tag, LIBNET_TCP_H);
		if (data_tag < 0) {
			printf("failed to add payload:%s\n", libnet_geterror(handle));
			//libnet_destroy(handle); /* 释放句柄 */
			return -1;
		}
		tcp_tag = libnet_build_tcp(
				src_port,                    /* 源端口 */
				dst_port,           		 /* 目的端口 */
				seq,                    /* 序列号 */
				0,                    /* 确认号 */
				TH_SYN,        		/* Control flags */
				0,                    /* 窗口尺寸 */
				0,                        /* 校验和,0为自动计算 */
				0,                        /* 紧急指针 */
				LIBNET_TCP_H + payload_s, /* 长度 */
				payload,                    /* 负载内容 */
				payload_s,                /* 负载内容长度 */
				handle,                    /* libnet句柄 */
				0                       /* 新建包 */
				);
		if (tcp_tag == -1) {
			printf("libnet_build_tcp failure\n");
			//libnet_destroy(handle); /* 释放句柄 */
			return -1;
		};
		/* 构造IP协议块 */
		ip_tag = libnet_build_ipv4(
				LIBNET_IPV4_H + LIBNET_TCP_H + payload_s, /* IP协议块的总长,*/
				0, /* tos */
				(u_short) libnet_get_prand(LIBNET_PRu32), /* id,随机产生0~65535 */
				0, /* frag 片偏移 */
				(u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
				proto, /* 上层协议 */
				0, /* 校验和，此时为0，表示由Libnet自动计算 */
				src_ip, /* 源IP地址,网络序 */
				dst_ip, /* 目标IP地址,网络序 */
				NULL, /* 负载内容或为NULL */
				0, /* 负载内容的大小*/
				handle, /* Libnet句柄 */
				0 /* 协议块标记可修改或创建,0表示构造一个新的*/
				);
		if (ip_tag == -1) {
			printf("libnet_build_ipv4 failure\n");
			//libnet_destroy(handle); /* 释放句柄 */
			return -1;
		};

		record_start_time(nr);
		ret = libnet_write(handle); /* 发送数据包*/
		//printf("packet_size:%d\n", ret);
		if (ret < packet_size) {
			printf("send tcp package failed:%d, errno:%s\n", packet_size, strerror(errno));
			//libnet_destroy(handle); /* 释放句柄 */
			return -1;
		}
		/* syn->ack 及时收发包 */
		usleep(1000 * trace_para.delay);
		// 清除包，否则会有包过长问题
		libnet_clear_packet(handle);
		seq++;
	}

	//libnet_destroy(handle); /* 释放句柄 */
	return 0;
}


static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct tcptrace_map_value *trace = (struct tcptrace_map_value*)data;
	int direction;

	for (int i = 0; i < PT_MAX; i++) {
		if (trace->entries[i].ns) {
			direction = trace->entries[i].padding;
			switch (direction) {
				case TCPTRACE_DIRECTION_OUT:
					trace_time.time[trace_time.out_id].times[trace->entries[i].function_id] = trace->entries[i].ns;
					break;
				case TCPTRACE_DIRECTION_IN:
					trace_time.time[trace_time.in_id].times[trace->entries[i].function_id] = trace->entries[i].ns;
					break;
				default:
					printf("no direction:%d\n", direction);
					break;
			}
		}
#ifdef DEBUG
		printf("cpu:%d, func id:%d, timestamp:%lu, dire:%d, num:%d\n", cpu, trace->entries[i].function_id,
				trace->entries[i].ns, trace->entries[i].padding, trace_time.out_id);
#endif
	}
	switch (direction) {
		case TCPTRACE_DIRECTION_OUT:
			trace_time.out_id++;
			break;
		case TCPTRACE_DIRECTION_IN:
			if (trace_para.file) {
				json_dump(trace_time.in_id);
			} else {
				image_show(trace_time.in_id);
			}
			trace_time.in_id++;
			break;
		default:
			printf("no direaction,:%d\n", direction);
			break;
	}
	// exit when receive last package
	if (trace_time.in_id == trace_para.pack_nr) {
		kill(getpid(), SIGINT);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static int trace(void)
{
	 /* 初始化Libnet */
	if ((handle = libnet_init(LIBNET_RAW4, NULL, error)) == NULL) {
		printf("libnet_init failure:%s\n", error);
		return -1;
	}
	probe(trace_para.pack_nr, trace_para.tuple.src_ip, trace_para.tuple.dst_ip,
			trace_para.tuple.src_port, trace_para.tuple.dst_port);
	libnet_destroy(handle); /* 释放句柄 */

	return 0;
}

static void tcpping_event_printer(int perf_map_fd)
{
    int err;
    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb = handle_lost_events,
    };
    struct perf_buffer *pb = NULL;
#ifdef DEBUG
    int i, j;
#endif

    pb = perf_buffer__new(perf_map_fd, 256, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        printf("failed to open perf buffer: %d\n", err);
        goto cleanup;
    }
    err = trace();
    if (err) {
	    goto cleanup;
    }
    /* polling the data */
    while (1) {
        err = perf_buffer__poll(pb, 200);
        if (err < 0 && errno != EINTR) {
            printf("Error polling perf buffer: %d\n", err);
            goto err;
        }
	if (exiting)
		break;
    }
#ifdef DEBUG
    for (i = 0; i < trace_time.size; i++) {
	    printf("===========package:%d============\n", i);
	    for (j = 0; j < 10; j++) {
		    if (trace_time.time[i].times[j]) {
		    	printf("func id:%d, timestamp:%llu, \n", j, trace_time.time[i].times[j]);
		    }
	    }
    }
#endif

err:
    free(trace_time.time);
    trace_time.time = NULL;
cleanup:
    perf_buffer__free(pb);
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void get_btf_path(void)
{
	FILE *fp = NULL;
	char version[64] = {};
	char *sysak_env_path = NULL;

	fp = popen("uname -r", "r");
	if (!fp) {
		printf("uname -r open failed, error:%s\n", strerror(errno));
		return;
	}
	fgets(version, sizeof(version), fp);
	strcat(btf_path_buf, version);

	// get btf from sysak first
	sysak_env_path = getenv("SYSAK_WORK_PATH");
	if (sysak_env_path) {
		memset(btf_path_buf, 0, sizeof(btf_path_buf));
		snprintf(btf_path_buf, BTF_PATH_MAX, "%s/tools/vmlinux-btf/vmlinux-%s", sysak_env_path, version);
	}

	btf_path_buf[strlen(btf_path_buf) - 1] = '\0';
#ifdef DEBUG
	printf("kernel version:%s, size:%ld\n", btf_path_buf, strlen(btf_path_buf));
#endif
	pclose(fp);
}

static void tcpping_update_tuple_info(int fd, struct tuple_info *tuple)
{
	int err;
	int key = 0;

	err = bpf_map_update_elem(fd, &key, tuple, 0);
	if (err != 0)
		fprintf(stderr, "bpf_map_update_ele error:%d %s",
				errno, strerror(errno));
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int is_numer(char *s)
{
	int i;
	if (!s || !s[0])
		return 0;
	for (i = 0; s[i]; i++) {
		if (!isdigit((unsigned char)s[i]))
			return 0;
	}
	return 1;
}

static int para_parse(int argc, char **argv)
{
	int opt;
	int err;

	while ((opt = getopt(argc, argv, "s:p:o:c:t:d:u:h")) != -1) {
		switch (opt) {
			case 'p':
				if (!is_numer(optarg))
					return -1;
				trace_para.tuple.src_port = atoi(optarg);
				break;
			case 'q':
				if (!is_numer(optarg))
					return -1;
				trace_para.tuple.dst_port = atoi(optarg);
				break;

			case 's':
				trace_para.tuple.src_ip = inet_addr(optarg);
				break;
			case 'd':
				trace_para.tuple.dst_ip = inet_addr(optarg);
				break;
			case 'c':
				if (!is_numer(optarg))
					return -1;
				trace_para.pack_nr = atoi(optarg);
				break;
			case 'o':
				/*
				if (!is_numer(optarg))
					return -1;
				trace_para.output_mode = atoi(optarg);
				*/
				if (optarg) {
					err = trace_output_init(optarg);
					if (err != 0)
						return err;
				}
				break;
			case 't':
				if (!is_numer(optarg))
					return -1;
				trace_para.delay = atoi(optarg);
				break;
			case 'u':
				trace_para.cpu = atoi(optarg);
				break;

			case 'h':
			default:
				fprintf(stderr, "Usage:[-d dip] [-s sip][-c package count] [-o output mode]\n");
				fprintf(stderr, "[-t send delay ms] [-p sport] [-q dport] [-u cpu affinity]\n");
				fprintf(stderr, "example sudo ./tcpping -s 11.160.62.45 -d 11.160.62.49 -c 10 -o /tmp/tcpping.json\n");
				exit(EXIT_FAILURE);
		}
	}
	return 0;
}

void set_cpu(int cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

int main(int argc, char **argv)
{
	struct tcpping_bpf *obj = NULL;
	int err = 0;

	err = para_parse(argc, argv);
	if (err) {
		printf("parameter parse failed, err:%d\n", err);
		goto cleanout;
	}

	if (trace_para.cpu != -1) {
		set_cpu(trace_para.cpu);
	}
	bump_memlock_rlimit();
	get_btf_path();
	libbpf_set_print(libbpf_print_fn);
	//DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	//open_opts.btf_custom_path = btf_path_buf;
	//open_opts.btf_custom_path = "/boot/vmlinux-4.19.91-007.ali4000.alios7.x86_64";
#ifdef DEBUG
	printf("%s, size:%ld\n", open_opts.btf_custom_path,
			strlen(open_opts.btf_custom_path));
#endif
	//obj = tcpping_bpf__open_opts(&open_opts);
	obj = tcpping_bpf__open();
	if (!obj) {
		err = -1;
		printf("failed to open BPF object\n");
		goto cleanout;
	}
	err = tcpping_bpf__load(obj);
	if (err) {
		printf("failed to load BPF object\n");
		goto cleanup;
	}
	err = tcpping_bpf__attach(obj);
	if (err) {
		printf("failed to attach BPF object\n");
		goto cleanup;
	}
	signal(SIGINT, sig_handler);

	tcpping_update_tuple_info(bpf_map__fd(obj->maps.tuple_map),
				    &trace_para.tuple);

	tcpping_event_printer(bpf_map__fd(obj->maps.perf_map));

cleanup:
	tcpping_bpf__destroy(obj);
cleanout:
	trace_output_close();
	return err;
}
