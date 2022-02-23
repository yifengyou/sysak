#include "tsar.h"

#define SERVER_PORT 9200
#define ERROR_MSG "HTTP/1.1 404 Not Found\r\n"

enum {
	REQUEST_METRIC,
	REQUEST_MAX
};

static int get_request(const char *buf)
{
	char req_str[32];

	sscanf(buf, "GET /%s HTTP", req_str);
	if (strcmp(req_str, "metric") == 0)
		return REQUEST_METRIC;

	return REQUEST_MAX;
}

void output_http(int sk)
{
	int         i, j, k, n = 0;
	char        detail[LEN_1M] = {0};
	struct      module *mod;
	static char line[LEN_10M] = {0};
	char http_header[LEN_64];
	char opt_line[LEN_64];
	char *precord, *psub;
	double    *st_array;

	line[0] = 0;

	for (i = 0; i < statis.total_mod_num; i++) {
		mod = mods[i];
                if (mod->enable && strlen(mod->record)) {
                        precord = mod->record;
                        j = 0;
                        for (j = 0; j < mod->n_item; j++) {
                                if (mod->n_item > 1) {
                                        psub = strstr(precord, "=");
                                        if (!psub)
                                                break;
                                        *psub = 0;
                                        snprintf(opt_line, LEN_64, "%s{%s,", mod->opt_line+2, precord);
                                        precord = strstr(psub + 1, ";");
					if (precord)
						precord = precord + 1;
                                } else {
                                        snprintf(opt_line, LEN_64, "%s{", mod->opt_line+2);
                                }

                                st_array = &mod->st_array[j * mod->n_col];
                                for (k = 0; k < mod->n_col; k++) {
                                        n = snprintf(detail, LEN_1M, "%s%s} %6.2f\n", opt_line, trim(mod->info[k].hdr, LEN_128), st_array[k]);
                                        if (n >= LEN_1M - 1) {
                                                do_debug(LOG_FATAL, "mod %s lenth is overflow %d\n", mod->name, n);
                                        }
                                        /* one for \n one for \0 */
                                        if (strlen(line) + strlen(detail) >= LEN_10M - 2) {
                                                do_debug(LOG_FATAL, "tsar.data line lenth is overflow line %d detail %d\n", strlen(line), strlen(detail));
                                        }
                                        strcat(line, detail);
                                }
                        }
                }
	}

	strcat(line, "\n");

	sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Length: %d \r\n\r\n",
			(int)strlen(line));
	write(sk, http_header, strlen(http_header));
	write(sk, line, strlen(line));
}


static void handle_metric(int sk)
{
	pthread_mutex_lock(&module_record_mutex);
	init_module_fields();
	/*read twice for metrics which need compute diff*/
	collect_record();
	collect_record_stat();
	usleep(50000);
	collect_record();
	collect_record_stat();
	output_http(sk);
	pthread_mutex_unlock(&module_record_mutex);
}

int http_server(void)
{
	struct sockaddr_in srvaddr;
	int sk, res, sockopt = 1;

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if(sk < 0) {
		printf("create socket error!\n");
		return -1;
	}

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(SERVER_PORT);
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int));

	res = bind(sk, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
	if(res < 0) {
		printf("bind error!\n");
		close(sk);
		return -1;
	}

	listen(sk, 10);

	while(1) {
		struct sockaddr_in cli_addr;
		socklen_t len = sizeof(cli_addr);
		int csk;

		csk = accept(sk, (struct sockaddr *)&cli_addr, &len);
		if(csk < 0) {
			printf("accept error!\n");
			close(sk);
			return -1;
		}

		char buff[1024] = {0};
		int size = read(csk, buff, sizeof(buff));

		if (size > 0 && get_request(buff) == REQUEST_METRIC)
			handle_metric(csk);
		else
			write(csk, ERROR_MSG, strlen(ERROR_MSG));
		
	        close(csk);
    }

    close(sk);

    return 0;
}
