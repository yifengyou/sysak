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
	int         i, n = 0;
	char        detail[LEN_1M] = {0};
	struct      module *mod;
	static char line[LEN_10M] = {0};
	char http_header[64];

	line[0] = 0;

	for (i = 0; i < statis.total_mod_num; i++) {
		mod = mods[i];
		if (mod->enable && strlen(mod->record)) {
			n = snprintf(detail, LEN_1M, "%s %s\n", mod->opt_line, mod->record);
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

	strcat(line, "\n");

	sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Length: %d \r\n\r\n",
			(int)strlen(line));
	write(sk, http_header, strlen(http_header));
	write(sk, line, strlen(line));
}


static void handle_metric(int sk)
{
        collect_record();
        output_http(sk);
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
