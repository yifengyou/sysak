#!/bin/sh
#****************************************************************#
# ScriptName: loadtask.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-06 10:53
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-06 10:53
# Function:
#***************************************************************#
usage() {
	echo "sysak loadtask: show all tasks of load contribution"
	echo "options: -h, help information"
	echo "         -m maxload, only show tasks when load reach maxload "
	echo "         -f datafile, file for output"
	echo "         -i interval, the interval checking the load"
	echo "         -d, run as deamon"
	echo "         -s, show summary result"
}

uninterrupt_cnt=0
running_cnt=0

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
						uninterrupt_cnt=$(($uninterrupt_cnt+1))
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
						running_cnt=$(($running_cnt+1))
					fi;
				fi;
			done;
		fi;
	done

}

#sort by name
show_result() {
	cat $datafile | grep "load reson"
	cat $datafile | grep "caused by"
	echo "top load tasks:"
	cat $datafile | grep Name | awk '{print $2}' | uniq -c | sort -nr
}

current_analyse() {
	date > $datafile
	cat /proc/loadavg >> $datafile
	load=`cat /proc/loadavg | awk '{print $1}'`
	cpu_util=(`mpstat $cpuarg 1 1 | grep Average | awk '{print $3" "$5" "$6" "$7" "$8" "$12}'`)
	echo "cpu: $cpu_util" >> $datafile
	if [ $(echo "$load < 5" | bc) -eq 1 ] ;then
		echo "load reson: not high" >> $datafile
		return
	fi

	running_dump
	uninterrupt_dump
	usr_util=${cpu_util[0]}
	sys_util=${cpu_util[1]}
	io_wait=${cpu_util[2]}
	irq_util=${cpu_util[3]}
	soft_util=${cpu_util[4]}
	cpu_idle=${cpu_util[5]}
	if [ $(echo "$usr_util > ((100-$cpu_idle)*0.4)" | bc) -eq 1 ]; then
		high_cost="user "
	fi
	if [ $(echo "$sys_util > ((100-$cpu_idle)*0.2)" | bc) -eq 1 ]; then
		high_cost+="sys "
		extra_cmd="[sysmonitor]"
		extra_info="high memory or kernel competition"
	fi
	if [ $(echo "$irq_util > ((100-$cpu_idle)*0.05)" | bc) -eq 1 ]; then
		high_cost="irq "
		extra_cmd+="[cpuirq]"
	fi
	if [ $(echo "$soft_util > ((100-$cpu_idle)*0.05)" | bc) -eq 1 ]; then
		high_cost="softirq "
		extra_info+="high network competition"
	fi
	if [ $(echo "$io_wait > ((100-$cpu_idle)*0.1)" | bc) -eq 1 ]; then
		high_wait="io "
		extra_cmd+="[iolantency]"
	fi
	mutex_cnt=`cat $datafile | grep mutex | wc -l`
	if [ $mutex_cnt -gt 5 ]; then
		high_wait+="mutex "
		#extra_cmd+="[lockcheck]"
	fi

	if [ $(echo "$load*0.2 > $uninterrupt_cnt" | bc) -eq 1 ]; then
		echo "load reason: high $high_cost cpu cost" >> $datafile
	else
		if [ $(echo "$load*0.6 < $uninterrupt_cnt" | bc) -eq 1 ]; then
			echo "load reason: high $high_wait wait" >> $datafile
		else
			echo "load reason: mixed press by high $high_cost and $high_wait wait" >> $datafile
		fi
	fi

	if [ -n "$extra_info" ]; then
		echo this may caused by $extra_info, you can contact kernel support of use more sysak$extra_cmd tools >> $datafile
	fi
}

history_analyse() {
	echo "use tsar"
}

load_analyse() {
	if [ -z $load_time ]; then
		current_analyse
	else
		history_analyse
	fi

	if [ "$summary" == "true" ];then
		show_result
	fi
}

monitor() {
	while :;
	do
		load=`cat /proc/loadavg | awk '{print $1}' | awk -F. '{print $1}'`
		if [ $load -gt $max_load ]; then
			current_analyse
			if [ "$deamon" != "true" ];then
				exit
			fi
		fi

		sleep $interval
	done
}

interval=5
datafile=/var/log/sysak/loadtask.log
max_load=0
while getopts 'm:f:i:t:dsh' OPT; do
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
		"t")
			load_time="$OPTARG"
			;;
		"d")
			deamon="true"
			;;
		"s")
			summary="true"
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
	load_analyse
fi
