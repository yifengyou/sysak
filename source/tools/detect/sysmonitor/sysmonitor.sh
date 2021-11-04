#!/bin/sh
#****************************************************************#
# ScriptName: sys_monitory.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-06 10:53
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-06 10:53
# Function:
#***************************************************************#
maxsys=20
interval=5
datafile=/var/log/sysak/sysmonitor.data
lasttime=10

usage() {
	echo "sysak sys_monitor: auto perf when sys util over threshold"
	echo "options: -h, help information"
	echo "         -m maxsys, auto perf when sys util over threshold  "
	echo "         -c cpu, cpu to mointor, default the total util to monitor"
	echo "         -f datafile, file for output"
	echo "         -i interval, the interval checking the sys util"
	echo "         -l lasttime, perf record time, default to 10 seconds"
}

monitor() {
	while :;
	do
		sys_util=`mpstat $cpuarg 1 1 | awk '{print $5}' | awk 'END{print $1}'`
		if [ `expr $sys_util \> $maxsys` -eq 0 ]; then
			perf record -a -g -o $datafile sleep $lasttime;
			exit
		fi

		sleep $interval
	done
}

while getopts 'm:f:c:i:lh' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"m")
			maxsys=$OPTARG
			;;
		"f")
			datafile=$OPTARG
			;;
		"c")
			cpuarg="-P $OPTARG"
			;;
		"i")
			interval="$OPTARG"
			;;
		"l")
			lasttime="$OPTARG"
			;;
		*)
			usage
			exit -1
		;;
	esac
done

monitor
