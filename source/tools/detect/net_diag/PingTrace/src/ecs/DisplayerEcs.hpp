#ifndef DISPLAYER_ECS_H
#define DISPLAYER_ECS_H

#include "display/Displayer.h"
#include "ecs/NetTopology.h"
#include "ecs/TimeStampRecorderEcs.h"
#include "bpf/map_define.h"
#include <curses.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <log4cpp/Category.hh>
#include <log4cpp/Appender.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/Layout.hh>
#include <log4cpp/PassThroughLayout.hh>

namespace pingtrace
{
class EcsDisplayer : public Displayer
{
  public:
	EcsDisplayer(std::shared_ptr<OutPuter> output) : Displayer(output) {}
	virtual ~EcsDisplayer(){};
	virtual void print(const EcsTimeStampResults &tsr, uint64_t threshold_ns){};
	virtual void end_print(const EcsTimeStampStat &tss){};

	static std::shared_ptr<EcsDisplayer> init_displayer(options *opt);
};

class EcsJsonDisplayer : public EcsDisplayer
{
  public:
	EcsJsonDisplayer(std::shared_ptr<OutPuter> output) : EcsDisplayer(output) {}
	void sequence_print(const EcsTimeStampResults &tsr, rapidjson::Writer<rapidjson::StringBuffer> &w)
	{
		if (tsr.timeout)
			return;
		w.StartObject();
		w.Key("meta");
		w.StartObject();
		w.Key("seq");
		w.Uint64(tsr.meta.seq);
		w.Key("start_ns");
		w.Uint64(tsr.meta.ts_start);
		w.EndObject();

		w.Key("points");
		w.StartArray();
		for (auto &point : tsr.points) {
			w.StartObject();
			w.Key("point");
			w.String(EcsNetTopology::get_points_name(point.point_id));
			w.Key("ts");
			if (point.mask)
			w.Uint64(point.ts);
			else
			w.Int64(-1);
			w.EndObject();
		}
		w.EndArray();

		w.Key("delays");
		w.StartArray();
		for (auto &delay : tsr.delay) {
			w.StartObject();
			w.Key("delay");
			w.String(EcsNetTopology::get_delay_name(delay.delay_id));
			w.Key("ts");
			if (delay.mask)
			w.Uint64(delay.ts);
			else
			w.Int64(-1);
			w.EndObject();
		}
		w.EndArray();

		w.EndObject();
	}
	void statistics_print(const EcsTimeStampStat &stat, rapidjson::Writer<rapidjson::StringBuffer> &w)
	{
		w.StartObject();
		w.Key("stat");
		w.StartObject();
		w.Key("packet_num");
		w.StartArray();
		w.StartObject();
		w.Key("name");
		w.String("send_num");
		w.Key("num");
		w.Uint64(stat.packet_num.send_num);
		w.EndObject();

		w.StartObject();
		w.Key("name");
		w.Key("reply_num");
		w.Key("num");
		w.Uint64(stat.packet_num.reply_num);
		w.EndObject();

		w.StartObject();
		w.Key("name");
		w.Key("lost_num");
		w.Key("num");
		w.Uint64(stat.packet_num.lost_num);
		w.EndObject();
		w.EndArray();

		w.Key("stage");
		w.StartArray();
		for (auto stage : stat.stage) {
			w.StartObject();
			if (stage.mask) {
			w.Key("delay");
			w.String(EcsNetTopology::get_delay_name(stage.delay_id));
			w.Key("max");
			w.Uint64(stage.max_delay);
			w.Key("min");
			w.Uint64(stage.min_delay);
			w.Key("avg");
			w.Uint64(stage.avg_delay);
			} else {
			w.Key("delay");
			w.String(EcsNetTopology::get_delay_name(stage.delay_id));
			w.Key("max");
			w.Int64(-1);
			w.Key("min");
			w.Int64(-1);
			w.Key("avg");
			w.Int64(-1);
			}
			w.EndObject();
		}
		w.EndArray();
		w.EndObject();
		w.EndObject();
	}

  public:
	virtual void print(const EcsTimeStampResults &tsr, uint64_t threshold_ns)
	{
		rapidjson::StringBuffer sb;
		rapidjson::Writer<rapidjson::StringBuffer> w(sb);

		sequence_print(tsr, w);
		if (tsr.timeout || tsr.total_delay_ns() < threshold_ns)
			return;
		output->write(sb.GetString());
	}
	virtual void end_print(const EcsTimeStampStat &tss)
	{
		rapidjson::StringBuffer sb;
		rapidjson::Writer<rapidjson::StringBuffer> w(sb);

		statistics_print(tss, w);
		output->end_write(sb.GetString());
	}
};
class EcsImageDisplayer : public EcsDisplayer
{
	WINDOW *mywindow;

  public:
	EcsImageDisplayer() : EcsDisplayer(std::make_shared<NullOutPuter>())
	{
		mywindow = initscr();
		cbreak();
	}
	~EcsImageDisplayer() { endwin(); }

  private:
	char *text_center(char *buff, int total_len, int valid_len)
	{
		int left = 0;
		if (valid_len >= total_len)
			return buff;
		left = (total_len - valid_len + 1) / 2;
		std::reverse(buff, buff + total_len - left);
		std::reverse(buff + total_len - left, buff + total_len);
		std::reverse(buff, buff + total_len);
		return buff;
	}
	char *num_align(uint32_t t)
	{
#define NUM_MAX_LEN 12
		static char s[NUM_MAX_LEN];
		int i;

		memset(s, 0, sizeof(s));
		sprintf(s, "%-11d", t);
		for (i = 0; i < NUM_MAX_LEN; ++i)
			if (s[i] == ' ')
			break;
		return text_center(s, NUM_MAX_LEN - 1, i);
#undef NUM_MAX_LEN
	}
	char *ip_align(in_addr_t dstip)
	{
		struct in_addr ip = {dstip};
		static char data[16];

		sprintf(data, "%-15s", inet_ntoa(ip));
		return text_center(data, sizeof(data) - 1, strlen(data) - 1);
	}

	void stat_print(const EcsTimeStampStat &stat)
	{
		auto &ptn = stat.packet_num;
		auto &stages = stat.stage;
		printw("%20s%-15s%-15s%-15s\n", "", "send_num", "reply_num", "lost_num");
		printw("%20s%-15d%-15d%-15d\n\n", "", ptn.send_num, ptn.reply_num, ptn.lost_num);
		printw("%-20s%-15s%-15s%-15s\n", "stage", "max", "min", "avg");
		for (auto &stage : stages) {
			if (!EcsNetTopology::is_image_display_stat_white_list(stage.delay_id))
				continue;
			if (stage.mask)
				printw("%-20s%-15d%-15d%-15d\n", EcsNetTopology::get_delay_name(stage.delay_id), stage.max_delay, stage.min_delay, stage.avg_delay);
			else
				printw("%-20s%-15s%-15s%-15s\n", EcsNetTopology::get_delay_name(stage.delay_id), "-", "-", "-");
		}
	}

	static std::string delay_str(const EcsTimeStampResults &tsr, int idx)
	{
		if (tsr.delay[idx].mask)
			return std::to_string(tsr.delay[idx].ts);
		return "-";
	}

	void print_impl(const EcsTimeStampResults &tsr)
	{
#define MASK(idx) (tsr.points[idx].mask ? 'X' : '.')
#define DELAY(idx) delay_str(tsr, EcsNetTopology::idx).c_str()
#define DELAY_X(idx) num_align(tsr.delay[EcsNetTopology::idx].ts)
#define P printw
		P("+---------------------------------ping-trace---------------------------------+\n");
		P("|  seq:%-10d                                                unit: %4s  |\n", tsr.meta.seq, tsr.meta.time_unit.c_str());
		P("|                                                                            |\n");
		P("|               +-------+                        +---------------+           |\n");
		P("|               | local | <----%s---->  |%15s|           |\n", DELAY_X(D_TOTAL), ip_align(tsr.meta.dstip));
		P("|               +-------+                        +---------------+           |\n");
		P("|                                                                            |\n");
		P("|              |            ^                                                |\n");
		P("|              |            |                                                |\n");
		P("|       User   %c            %c                                  User          |\n", MASK(P_L_TX_USER), MASK(P_L_RX_USER));
		P("|         -----+------------+- %-11s     -----------------             |\n", DELAY(D_L_RX_TASK_QUEUE));
		P("|              |            %c                                                |\n", MASK(P_L_RX_WAKEUP));
		P("|              |            |%-11s        +------%c<-----               |\n", DELAY(D_L_RX_TASK_WAKING), MASK(P_R_RX_ICMPRCV));
		P("|              |            %c                   |            |               |\n", MASK(P_L_RX_SKDATAREADY));
		P("|              |            |%-11s        |            |               |\n", DELAY(D_L_RX_KERN));
		P("|              |            |                   |            |               |\n");
		P("|   %11s|            |        %11s|            |               |\n", DELAY(D_L_TX_KERN), DELAY(D_R_TX_KERN));
		P("|              |            |                   |            |%-11s    |\n", DELAY(D_R_RX_KERN));
		P("|              %c            %c                   |            |               |\n", MASK(P_L_TX_DEVQUEUE), MASK(P_L_RX_IPRCV));
		P("|   %11s|            |%-11s        |            |               |\n", DELAY(D_L_TX_QDISC), DELAY(D_L_RX_SOFTIRQ));
		P("|       Kern   %c            %c                   %c            %c Kern          |\n", MASK(P_L_TX_DEVOUT), MASK(P_L_RX_SOFTIRQ), MASK(P_R_TX_DEVOUT), MASK(P_R_RX_IPRCV));
		P("|         -----+------------+-----           ---+------------+----           |\n");
		P("|              |            ^                   |            ^               |\n");
		P("|       NIC    V            |                   V            | NIC           |\n");
		P("|         -----+------------+-----           ---+------------+----           |\n");
		P("|              |            |    %11s    |            |               |\n", DELAY_X(D_L_RX_INLINK));
		P("|              |            +-------------------+            |               |\n");
		P("|              +---------------------------------------------+               |\n");
		P("|                                %11s                                 |\n", DELAY_X(D_L_TX_OUTLINK));
		P("+----------------------------------------------------------------------------+\n");
		stat_print(tsr.stat);
#undef DELAY_X
#undef DELAY
#undef MASK
#undef P

		move(0, 0);
		refresh();
	}

  public:
	virtual void print(const EcsTimeStampResults &tsr, uint64_t threshold_ns)
	{
		if (tsr.timeout || tsr.total_delay_ns() < threshold_ns)
			return;
		print_impl(tsr);
	}
	virtual void end_print(const EcsTimeStampStat &tss)
	{
		stat_print(tss);
	}
};

class EcsCombinedDisplayer : public EcsDisplayer
{
	EcsJsonDisplayer dis_json;
	EcsImageDisplayer dis_image;

  public:
	EcsCombinedDisplayer(options *opt) :
		dis_json(std::make_shared<LogOutPuter>(opt)),
		dis_image(),
		EcsDisplayer(std::make_shared<NullOutPuter>())
	{}
	virtual void print(const EcsTimeStampResults &tsr, uint64_t threshold_ns)
	{
		if (tsr.timeout)
			return;
		if (tsr.total_delay_ns() >= threshold_ns)
			dis_json.print(tsr, 0);
		dis_image.print(tsr, 0);
	}
	virtual void end_print(const EcsTimeStampStat &tss)
	{
		dis_json.end_print(tss);
		dis_image.end_print(tss);
	}
};

std::shared_ptr<EcsDisplayer> EcsDisplayer::init_displayer(options *opt)
{
	if (opt->output == DIS_IMAGE_LOG)
		return std::make_shared<EcsCombinedDisplayer>(opt);
	else if (opt->output == DIS_IMAGE)
		return std::make_shared<EcsImageDisplayer>();
	else if (opt->output == DIS_JSON)
		return std::make_shared<EcsJsonDisplayer>(std::make_shared<ConsoleOutPuter>(opt));

	return std::make_shared<EcsJsonDisplayer>(std::make_shared<LogOutPuter>(opt));
}
}; // namespace pingtrace

#endif