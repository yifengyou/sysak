#ifndef DISPLAYER_NAMESPACE_H
#define DISPLAYER_NAMESPACE_H

#include "display/Displayer.h"
#include "namespace/TimeStampRecorderNamespace.h"
#include "netmodel/TsList.h"

namespace pingtrace
{
class NamespaceJsonDisplayer : public Displayer
{
  public:
	NamespaceJsonDisplayer(std::shared_ptr<OutPuter> output) : Displayer(output) {}
	void sequence_print(const TsList &tsl, NamespaceTimeStampRecorder &recorder, rapidjson::Writer<rapidjson::StringBuffer> &w, uint32_t seq)
	{
		NamespaceTimeStampResult tsr = recorder.record(tsl);
		if (tsl.timeout)
			return;

		w.StartObject();

		w.Key("meta");
		w.StartObject();
		w.Key("seq");
		w.Uint64(seq);
		w.Key("start_ns");
		w.Uint64(tsl.start_ts);
		w.Key("end_ns");
		w.Uint64(tsl.end_ts);
		w.EndObject();

		w.Key("points");
		w.StartArray();
		for (auto &t : tsl.list) {
			w.StartObject();
			w.Key("nsid");
			w.Uint64(t.ns_id);
			w.Key("userid");
			w.Uint(t.user_id);
			w.Key("ifindex");
			w.Uint(t.ifindex);
			w.Key("funcid");
			w.String(NetTopology::get_points_name(t.function_id));
			w.Key("ts");
			w.Uint64(t.ts);
			w.EndObject();
		}
		w.EndArray();

		w.Key("delays");
		w.StartArray();
		for (int i = 0; i < tsr.delays.size(); ++i) {
			w.StartObject();
			w.Key("ts");
			w.Int64(tsr.delays[i]);
			w.Key("idx_start");
			w.Int(i);
			w.Key("idx_end");
			w.Int(i + 1);
			w.EndObject();
		}
		w.EndArray();

		w.EndObject();
	}
	void statistics_print(NamespaceTimeStampRecorder &recorder, rapidjson::Writer<rapidjson::StringBuffer> &w)
	{
		w.StartObject();
		w.Key("statistics");
		w.StartArray();
		for (auto const &x : recorder.get()) {
			auto const &key = x.first;
			auto const &value = x.second;
			w.StartObject();

			w.Key("start");
			w.StartObject();
			w.Key("nsid");
			w.Uint(key.start_id.nsid);
			w.Key("userid");
			w.Uint(key.start_id.userid);
			w.Key("ifindex");
			w.Uint(key.start_id.ifindex);
			w.Key("funcid");
			w.String(NetTopology::get_points_name(key.start_id.function_id));
			w.EndObject();

			w.Key("end");
			w.StartObject();
			w.Key("nsid");
			w.Uint(key.end_id.nsid);
			w.Key("userid");
			w.Uint(key.end_id.userid);
			w.Key("ifindex");
			w.Uint(key.end_id.ifindex);
			w.Key("funcid");
			w.String(NetTopology::get_points_name(key.end_id.function_id));
			w.EndObject();

			w.Key("stat");
			w.StartObject();
			w.Key("min_delay");
			w.Int(value.min_delay);
			w.Key("max_delay");
			w.Int(value.max_delay);
			w.Key("avg_delay");
			w.Int(value.sum_delay / value.num);
			w.Key("num");
			w.Int64(value.num);
			w.EndObject();

			w.EndObject();
		}
		w.EndArray();
		w.EndObject();
	}
	void print(const TsList &tsl, NamespaceTimeStampRecorder &recorder, uint64_t threshold_ns, uint32_t seq)
	{
		rapidjson::StringBuffer sb;
		rapidjson::Writer<rapidjson::StringBuffer> w(sb);

		sequence_print(tsl, recorder, w, seq);
		if (tsl.timeout || tsl.total_delay_ns() < threshold_ns)
			return;
		output->write(sb.GetString());
	}

	void end_print(NamespaceTimeStampRecorder &recorder)
	{
		rapidjson::StringBuffer sb;
		rapidjson::Writer<rapidjson::StringBuffer> w(sb);

		statistics_print(recorder, w);
		output->end_write(sb.GetString());
	}

	static std::shared_ptr<NamespaceJsonDisplayer> init(options *opt)
	{
		if (opt->output != DIS_JSON)
			return std::make_shared<NamespaceJsonDisplayer>(std::make_shared<LogOutPuter>(opt));
		return std::make_shared<NamespaceJsonDisplayer>(std::make_shared<ConsoleOutPuter>(opt));
	}
};

}; // namespace pingtrace

#endif