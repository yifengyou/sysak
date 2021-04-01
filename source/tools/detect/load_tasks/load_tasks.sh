#!/bin/sh
#****************************************************************#
# ScriptName: load_tasks.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-06 10:53
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-06 10:53
# Function:
#***************************************************************#
usage() {
	echo "sysak load_tasks: show all tasks of load contribution"
	echo "options: -h, help information"
	echo "         -m maxload, only show tasks when load reach maxload "
	echo "         -f datafile, file for output"
	echo "         -i interval, the interval checking the load"
	echo "         -d, run as deamon"
}

uninterrupt_dump() {
	echo "uninterrupt tasks:" >> $datafile
	for pid in $(ls /proc/);
	do
		if [ "$pid" -gt 0 ] 2>/dev/null; then
			for tid in $(ls /proc/$pid/task/ 2>/dev/null); do
				if [ "$tid" -gt 0 ] 2>/dev/null; then
					run=`cat /proc/$tid/status | grep "disk sleep" | wc -l`
					if  [ "$run" -gt 0 ] 2>/dev/null; then
						echo $tid >> $datafile
						cat /proc/$tid/status | grep Name >> $datafile
						cat /proc/$tid/stack >> $datafile
					fi;
				fi;
			done;
		fi;
	done
}

running_dump() {
	echo "running tasks:" >> $datafile
	for pid in $(ls /proc/);
	do
		if [ "$pid" -gt 0 ] 2>/dev/null; then
			for tid in $(ls /proc/$pid/task/ 2>/dev/null); do
				if [ "$tid" -gt 0 ] 2>/dev/null; then
					run=`cat /proc/$tid/status | grep "running" | wc -l`
					if  [ "$run" -gt 0 ] 2>/dev/null; then
						echo $tid >> $datafile
						cat /proc/$tid/status | grep Name >> $datafile
					fi;
				fi;
			done;
		fi;
	done

}

load_tasks() {
	date >> $datafile
	cat /proc/loadavg >> $datafile
	running_dump
	uninterrupt_dump
}

monitor() {
	while :;
	do
		load=`cat /proc/loadavg | awk '{print $1}' | awk -F. '{print $1}'`
		if [ $load -gt $max_load ]; then
			load_tasks
			if [ "$deamon" != "true" ];then
				exit
			fi
		fi

		sleep $interval
	done
}

interval=5
datafile=load.data
max_load=0
while getopts 'm:f:i:dh' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"m")
			max_load=$OPTARG
			;;
		"f")
			datafile=$OPTARG
			;;
		"i")
			interval="$OPTARG"
			;;
		"d")
			deamon="true"
			;;
		*)
			usage
			exit -1
		;;
	esac
done

if [ $max_load -gt 0 ];then
	monitor
else
	load_tasks
fi
