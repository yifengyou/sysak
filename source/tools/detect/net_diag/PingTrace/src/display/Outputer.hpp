#ifndef OUTPUTER_H
#define OUTPUTER_H

#include "log4cpp/Appender.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/PassThroughLayout.hh"
#include "log4cpp/RollingFileAppender.hh"
#include "common/options.hpp"
#include <stdio.h>

namespace pingtrace
{

class OutPuter
{
public:
	virtual void write(const std::string &str){};
	virtual void end_write(const std::string &str){};
};

class NullOutPuter : public OutPuter
{
};

class LogOutPuter : public OutPuter
{
	log4cpp::Category *seq;
	log4cpp::Category *stat;

public:
	LogOutPuter(options *opt)
	{
		std::string seq_log = opt->log_name + ".seq";
		std::string stat_log = opt->log_name + ".stat";

		log4cpp::Appender *seq_app = new log4cpp::RollingFileAppender("default", seq_log, opt->log_max_size, opt->log_max_backup, false, 420U);
		seq_app->setLayout(new log4cpp::PassThroughLayout());
		log4cpp::Category &seq = log4cpp::Category::getInstance(std::string("seq"));
		seq.addAppender(seq_app);

		log4cpp::Appender *stat_app = new log4cpp::RollingFileAppender("default", stat_log, opt->log_max_size, opt->log_max_backup, false, 420U);
		stat_app->setLayout(new log4cpp::PassThroughLayout());
		log4cpp::Category &stat = log4cpp::Category::getInstance(std::string("stat"));
		stat.addAppender(stat_app);
	}
	virtual void write(const std::string &str)
	{
		log4cpp::Category::getInstance(std::string("seq")).info("%s\n", str.c_str());
	}
	virtual void end_write(const std::string &str)
	{
		log4cpp::Category::getInstance(std::string("stat")).info("%s\n", str.c_str());
	}
};

class ConsoleOutPuter : public OutPuter
{
public:
	ConsoleOutPuter(options *opt) {}
	virtual void write(const std::string &str)
	{
		printf("%s\n", str.c_str());
		fflush(stdout);
	}
	virtual void end_write(const std::string &str)
	{
		printf("%s\n", str.c_str());
		fflush(stdout);
	}
};
} // namespace pingtrace

#endif