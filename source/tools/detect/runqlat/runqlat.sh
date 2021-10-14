#!/bin/bash
BASE=`pwd`
TMPSH=${BASE}/tmp.sh
target_pid=""
IF_MATCH_PID_CONSTRUCT1=""
IF_MATCH_PID_CONSTRUCT2=""


function usage(){
	echo "Usage:";
	echo "./runqlat.sh [OPTIONS]";
	echo "";
	echo "Options:";
	echo "  -p|--pid";
	echo "     PID of the process you want to measure sched latency";
	echo "  -h|--help";
	echo "     For help";
	echo "";
	echo "For example:";
	echo "measure sched latency of the given process "
	echo "./runqlat.sh.sh -p \${pid}";
	echo "measure sched latency of all the processes, i.e. system-wise"
	echo "./runqlat.sh"
}

function parse_args(){
	ARGS=`getopt -l pid:,help -o hp:  -- "$@" 2>/dev/null` || { usage; exit 1;}
	eval set -- "${ARGS}"
	while [ -n "$1" ]
	do
		case "$1" in
		-p|--pid)
			target_pid="$2"
			shift
			;;
		-h|--help)
			usage
			;;
		--)
			shift
			break
			;;
		esac
		shift
	done

}

function do_work() {

	if [ ! -z "${target_pid}" ]; then
		IF_MATCH_PID_CONSTRUCT1="if (args->pid == ${target_pid})"
		IF_MATCH_PID_CONSTRUCT2="if (args->prev_pid == ${target_pid})"
	fi

	cat > ${TMPSH} << EOF
		#!/usr/bin/env bpftrace
		#include <linux/sched.h>

		BEGIN
		{
			printf("Tracing CPU scheduler latency... Hit Ctrl-C to end.\n");
		}

		tracepoint:sched:sched_wakeup,
		tracepoint:sched:sched_wakeup_new
		{
			$IF_MATCH_PID_CONSTRUCT1
				@qtime[args->pid] = nsecs;
		}

		tracepoint:sched:sched_switch
		{

			if (args->prev_state == TASK_RUNNING) {
				$IF_MATCH_PID_CONSTRUCT2
					@qtime[args->prev_pid] = nsecs;
			}

			\$ns = @qtime[args->next_pid];
			if (\$ns) {
				@usecs = hist((nsecs - \$ns) / 1000);
			}
			delete(@qtime[args->next_pid]);
		}

		END
		{
			clear(@qtime);
		}
EOF

}

parse_args "$@";
do_work