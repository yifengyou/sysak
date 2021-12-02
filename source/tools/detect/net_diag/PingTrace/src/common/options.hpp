#ifndef OPTIONS_H
#define OPTIONS_H

#include "CLI/CLI.hpp"
#include "common/common.h"
#include "common/config.h"
#include <functional>
#include <string>

namespace pingtrace
{

struct options {
	bool exit;

	bool help;
	bool version;
	int interval_us;
	uint64_t runtime;
	std::string ip;
	int max_delay;
	unsigned long max_count;
	enum display_type output;
	bool run_client;
	bool run_server;
	bool debug;
	bool adaptive;
	std::string log_name;
	int64_t log_max_size;
	int64_t log_max_backup;
	enum run_mode mode;
	int entry_num;
	int packet_size;
	bool is_namespace;
	bool is_ns_local;
	uint32_t user_id;
	std::string btf_path;
	bool compat;

	options()
	{
		this->exit = false;
		this->help = false;
		this->version = false;

		this->interval_us = 1000000;
		this->runtime = -1;
		this->ip = "";

		this->max_delay = 0;
		this->max_count = INT64_MAX;
		this->output = DIS_JSON;
		this->run_client = false;
		this->run_server = false;
		this->debug = false;
		this->adaptive = false;

		this->log_name = config::log_name;
		this->log_max_size = config::log_max_size;
		this->log_max_backup = config::log_max_backup;
		this->mode = MODE_AUTO;

		this->entry_num = config::default_entry_num;
		this->packet_size = sizeof(pingtrace_pkt) + sizeof(pingtrace_timestamp) * this->entry_num;

		this->is_namespace = false;
		this->is_ns_local = false;
		this->user_id = 0;

		this->btf_path = "";

		this->compat = false;
	}

	int arg_parse(int argc, char **argv)
	{
		CLI::App app("PingTrace");

		app.set_help_flag();
		app.set_version_flag("-v,--version", config::version);
		app.add_flag("-h,--help", this->help, "print this help message and exit");
		app.add_flag("-s,--server", this->run_server, "run server");
		app.add_option("-c,--client", this->ip, "run client")->option_text("ip");
		app.add_option("-C,--count", this->max_count, "packet send count, default is infinity");
		app.add_option("-i", this->interval_us, "set send interval_us per ip in us, default is 1s")->option_text("interval_us");
		app.add_option("-t", this->runtime, "set pingtrace run time in second, default is infinity");
		app.add_flag("-A", this->adaptive, "ping adaptive, would be flooding");
		app.add_option("-m,--maxdelay", this->max_delay,
				"max_delay in us, if ping's delay is larger than "
				"max_delay, print it. default is 0",
				true)
			->option_text("us");
		app.add_option("-b", this->packet_size, std::string("packet size, at least ") + std::to_string(pingtrace_pkt::min_packet_size()), true);
		app.add_option("--log", this->log_name, "log name", true);
		app.add_option("--logsize", this->log_max_size, "log max size in bytes, default is 2M");
		app.add_option("--logbackup", this->log_max_backup, "log max backup num", true);

		std::map<std::string, enum run_mode> modes = {
			{"auto", MODE_AUTO},
			{"pingpong", MODE_PINGPONG},
			{"compact", MODE_COMPACT},
		};
		app.add_option("--mode", this->mode, "pingtrace mode, optional:compact, pingpong, or auto")
			->transform(CLI::CheckedTransformer(modes, CLI::ignore_case))
			->option_text("auto/pingpong/compact");

		std::map<std::string, enum display_type> outputs = {{"image", DIS_IMAGE}, {"json", DIS_JSON}, {"log", DIS_JSON_FILE}, {"imagelog", DIS_IMAGE_LOG}};
		app.add_option("-o,--output", this->output, "output mode, optional:image, json, log, imagelog")
			->transform(CLI::CheckedTransformer(outputs, CLI::ignore_case))
			->option_text("image/json/log/imagelog");

		app.add_flag("-n,--namespace", this->is_namespace, "get net namespace infos");
		app.add_flag("--nslocal", this->is_ns_local, "to tell PingTrace that local and remote is on same host");
		app.add_option("--userid", this->user_id, "specify user id to distinguish different node");
		app.add_option("--btf_path", this->btf_path, "specify custom btf vmlinux path");
		app.add_flag("--compat", this->compat, "compat with kernel 4.9");
		app.add_flag("--debug", this->debug, "used for debug, output more detail messages");

		try {
			app.parse(argc, argv);
			if (!this->ip.empty())
			this->run_client = true;
			if (this->help || (!this->run_client && !this->run_server))
			throw CLI::CallForHelp();
		} catch (const CLI::Error &e) {
			this->exit = true;
			return app.exit(e);
		}

		this->entry_num = pingtrace_pkt::packet_size_to_entry_num(this->packet_size);
		if (this->entry_num < config::packet_reserve_entry_num) {
			fprintf(stderr, "packet size is too small\n");
			return -1;
		}
		this->run_client = !this->ip.empty();
		return 0;
	}
};

}; // namespace pingtrace

#endif