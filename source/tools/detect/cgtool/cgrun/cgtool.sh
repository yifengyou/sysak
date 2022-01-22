#!/bin/bash
#****************************************************************#
# ScriptName: cgtool.sh
# Author: Bixuan Cui <cuibixuan@linux.alibaba.com>
# Create Date: 2022-01-07
# Function: 
#***************************************************************#
if [ "$SYSAK_WORK_PATH" != "" ]; then
WORK_PATH=$SYSAK_WORK_PATH
else
WORK_PATH=/usr/local/sbin/.sysak_compoents
fi

MEMCGUSAGE_BIN=$WORK_PATH/tools/memcg_usage
MEMCGSHOW_BIN=$WORK_PATH/tools/memcg_show
CPUACCTLOAD_BIN=$WORK_PATH/tools/cpuacct_load
CGCHECK_BIN=$WORK_PATH/tools/cgcheck

# arguments
usage()
{
	echo "cgtool: tools for analyzing cgroups"
	echo "Usage:"
	echo "  sysak cgtool [options] [cgtool [cgtoolargs]]"
	echo "  options: -h, help information"
	echo "           -l, list all tools for cgroup"
	echo "  cgtool:"
	echo "           tool name for list"
	echo "  cgtoolargs:"
	echo "           args for the tool, -h get more"
	echo "Examples:"
	echo "  sysak cgtool -l"
	echo "  sysak cgtool usage -h"
}

trace_list()
{
	echo "memcg_usage # tracing memory usage of the memory cgroup"
	echo "memcg_show # statistics of usage,rss,cache... of each memcg"
	echo "cpuacct_load # tracing cpu load for the cpuacct cgroup"
	echo "cgcheck # cgroup check in the system "
}

while getopts 'hl' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"l")
			trace_list
			exit 0
			;;
		*)
			usage
			exit 0
		;;
	esac
done

cgtool=${@:$OPTIND:1}
cgtoolcmd=${*:$OPTIND+1};

if [ "X${cgtool}" == "Xmemcg_usage" ]; then
	$MEMCGUSAGE_BIN $cgtoolcmd
elif [ "X${cgtool}" == "Xmemcg_show" ]; then
	$MEMCGSHOW_BIN $cgtoolcmd
elif [ "X${cgtool}" == "Xcpuacct_load" ]; then
	$CPUACCTLOAD_BIN $cgtoolcmd
elif [ "X${cgtool}" == "Xcgcheck" ]; then
	$CGCHECK_BIN $cgtoolcmd
else
	echo "not support tool:${cgtool}"
	exit -1
fi
