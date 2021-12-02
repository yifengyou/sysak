#include "pt/PingTraceClient.hpp"
#include "pt/PingTraceServer.hpp"
#include <stdio.h>

int main(int argc, char **argv)
{
	struct pingtrace::options opt;

	if (opt.arg_parse(argc, argv))
		return -1;
	if (opt.exit)
		return 0;

	if (pingtrace::BPFProg::preinit(opt.debug) < 0)
		return -1;

	try {
		if (opt.run_client) {
			pingtrace::PingTraceClient c;
			c.run(&opt);
		} else if (opt.run_server) {
			pingtrace::PingTraceServer s;
			s.run(&opt);
		}
	} catch (pingtrace::ping_exception &e) {
		fprintf(stderr, e.str);
		return -1;
	}

	return 0;
}
