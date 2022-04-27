#!/bin/sh
#****************************************************************#
# ScriptName: loadtask.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-06 10:53
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-06 10:53
# Function:
#***************************************************************#
TOOLS_ROOT="$SYSAK_WORK_PATH/tools"

usage() {
	echo "sysak loadtask: show all tasks of load contribution"
	echo "options: -h,          help information"
	echo "         -m maxload,  only show tasks when load reach maxload "
	echo "         -f datafile, file for output"
	echo "         -i interval, the interval checking the load"
	echo "         -d,          keep monitoring even if greater than maxload occurs.useful only if the -m option is set"
	echo "         -s,          show summary result. will insmod loadtask.ko"
	echo "         -k,          terminate running ${selftaskname} which started previously"
	echo "         -g,          default collect cpu perf flamegraph by cpu_flamegraph tool"
	echo "         -r datafile, read datafile created by '-f datafile' or by default(datafile directory /var/log/sysak/loadtask/) and show result"
}

uninterrupt_cnt=0
running_cnt=0
container=""

get_container() {
	if [ -f $TOOLS_ROOT/tcontainer ]; then
		container="`$TOOLS_ROOT/tcontainer -p $1`"
	else
		container=""
	fi
}

uninterrupt_dump() {
	local flag=0
	echo "uninterrupt tasks:" >> $tmpfile

	if [ -f $TOOLS_ROOT/taskstate ]; then
		cat $dtaskfile >> $tmpfile
	else
		for pid in $(ls /proc/);
		do
			flag=0
			if [ "$pid" -gt 0 ] 2>/dev/null; then
				for tid in $(ls /proc/$pid/task/ 2>/dev/null); do
					if [ "$tid" -gt 0 ] 2>/dev/null; then
						run=`cat /proc/$tid/status | grep "disk sleep" | wc -l`
						if  [ "$run" -gt 0 ] 2>/dev/null; then
							echo $tid >> $tmpfile
							if [ $flag -eq 0 ]; then
								get_container $pid
								flag=1
							fi
							echo "-----" >> $tmpfile
							#echo "`cat /proc/$tid/status | grep Name` $container" >> $tmpfile
							task_name="Task_`cat /proc/$tid/status | grep Name`"
							echo "$task_name $container" >> $tmpfile
							cat /proc/$tid/stack >> $tmpfile
							uninterrupt_cnt=$(($uninterrupt_cnt+1))
						fi;
					fi;
				done;
			fi;
		done
	fi
}

running_dump() {
	local flag=0
	echo "running tasks:" >> $tmpfile

	if [ -f $TOOLS_ROOT/taskstate ]; then
		cat $rtaskfile >> $tmpfile
	else
		for pid in $(ls /proc/);
		do
			flag=0
			if [ "$pid" -gt 0 ] 2>/dev/null; then
				for tid in $(ls /proc/$pid/task/ 2>/dev/null); do
					if [ "$tid" -gt 0 ] 2>/dev/null; then
						run=`cat /proc/$tid/status | grep "running" | wc -l`
						if  [ "$run" -gt 0 ] 2>/dev/null; then
							echo $tid >> $tmpfile
							if [ $flag -eq 0 ]; then
								get_container $pid
								flag=1
							fi

							#echo "`cat /proc/$tid/status | grep Name` $container" >> $tmpfile
							task_name="Task_`cat /proc/$tid/status | grep Name`"
							echo "$task_name $container" >> $tmpfile
							running_cnt=$(($running_cnt+1))
						fi;
					fi;
				done;
			fi;
		done
	fi
}

cal_sirq() {
	if [ $1 -eq 1 ]; then
		#exist softirq tool
		if [ $2 -eq 0 ]; then
			$TOOLS_ROOT/softirq -s $tmpsirqfile
		else
			$TOOLS_ROOT/softirq -s $tmpsirqfile -r $sirqspeedfile
		fi
	else
		local sirq=`cat /proc/softirqs`
		local cpu_num=`echo "$sirq" | head  -n 1 |  awk '{print NF}'`
		local i=1
		local arr_num=0

		while [ $i -le $sirq_num ]; do
			local j=0
			local tmp=$((i+1))
			local sirq_row_data=`echo "$sirq" | head -n $tmp | tail -n 1`
			local sum=`echo $sirq_row_data |  awk 'BEGIN{sum=0}{for(i=2; i<=NF; i++) sum+=$i} END{print sum}'`

			if [ $2 -eq 0 ]; then
				sirq_before[arr_num]=`echo $sirq_row_data |  awk '{print $1}'`
				arr_num=$((arr_num+1))
				sirq_before[arr_num]=$sum
			else
				sirq_after[arr_num]=`echo $sirq_row_data |  awk '{print $1}'`
				arr_num=$((arr_num+1))
				sirq_after[arr_num]=$sum
			fi

			arr_num=$((arr_num+1))
			i=$((i+1))
		done
	fi
}

cal_sirq_speed() {
	echo "softirq speed:" >> $tmpfile

	if [ $1 -eq 1 ]; then
		#exist softirq tool
		cat $sirqspeedfile >> $tmpfile
	else
		local arr_num=${#sirq_before[@]}
		local i=0

	while [ $i -lt $arr_num ]; do
			local diff=$((${sirq_after[$i+1]}-${sirq_before[$i+1]}))
			echo "      ${sirq_after[$i]} ${diff} count/s" >> $tmpfile
			i=$((i+2))
		done
	fi
}

#sort by name
show_result() {
	cat $1 | grep "load reason"
	cat $1 | grep "caused by"
	echo "top load tasks:"
	cat $1 | grep Task_Name | awk '{print $2 "  " $3}' | uniq -c | sort -nr
	cat $1 | grep -A $sirq_num "softirq speed:"
	echo ""
}

collect_global_framegraph() {
	if [ -f  $TOOLS_ROOT/cpu_flamegraph ]; then
		$TOOLS_ROOT/cpu_flamegraph -d 5 | xargs -I {} sudo cp {} $global_cpuflamegraph
		if [ -e $global_cpuflamegraph ];then
			sudo cp $global_cpuflamegraph $tmp_cpuflamegraph
		fi
	fi
}

current_analyse() {
	local high_sirq=0
	local exist_sirq_tool=0

	if [ -f $TOOLS_ROOT/softirq ]; then
		exist_sirq_tool=1
	fi

	if [ "$is_cpuflamegraph" == "true" ];then
		collect_global_framegraph
	fi
	echo "####################################################################################" > $tmpfile

	echo "Time: `date "+%Y-%m-%d %H:%M:%S"`" >> $tmpfile
	if [ -e $global_cpuflamegraph ];then
		echo "$global_cpuflamegraph" >> $tmpfile
	else
		echo "Failed to generate cpu flamwgrapg" >> $tmpfile
	fi
	load_proc=`cat /proc/loadavg`
	load_proc="load_proc: $load_proc"
	echo "$load_proc" >> $tmpfile
	if [ "$summary" == "true" ];then
		if [ -f "/sys/fs/cgroup/cpuacct/cpuacct.proc_stat" ]; then
			load_1=`echo $load_proc | awk -F " " '{print$2}'`
			load_5=`echo $load_proc | awk -F " " '{print$3}'`
			load_15=`echo $load_proc | awk -F " " '{print$4}'`

			r_count=`cat /sys/fs/cgroup/cpuacct/cpuacct.proc_stat | grep nr_running | awk -F " " '{print$2}'`
			d_count=`cat /sys/fs/cgroup/cpuacct/cpuacct.proc_stat | grep nr_uninterruptible | awk -F " " '{print$2}'`

			loadavg_r_1=$(echo "$r_count/($r_count+$d_count)*$load_1" | bc | awk '{printf "%.2f\n", $0}')
			loadavg_r_5=$(echo "$r_count/($r_count+$d_count)*$load_5" | bc | awk '{printf "%.2f\n", $0}')
			loadavg_r_15=$(echo "$r_count/($r_count+$d_count)*$load_15" | bc | awk '{printf "%.2f\n", $0}')
			loadavg_d_1=$(echo "$load_1-$loadavg_r_1" | bc | awk '{printf "%.2f\n", $0}')
			loadavg_d_5=$(echo "$load_5-$loadavg_r_5" | bc | awk '{printf "%.2f\n", $0}')
			loadavg_d_15=$(echo "$load_15-$loadavg_r_15" | bc | awk '{printf "%.2f\n", $0}')

			echo "loadavg_r: $loadavg_r_1 $loadavg_r_5 $loadavg_r_15" >> $tmpfile
			echo "loadavg_d: $loadavg_d_1 $loadavg_d_5 $loadavg_d_15" >> $tmpfile
		fi
	fi
	load=`cat /proc/loadavg | awk '{print $1}'`

	cal_sirq $exist_sirq_tool 0
	cpu_util=(`mpstat $cpuarg 1 1 | awk 'END {print $3" "$5" "$6" "$7" "$8" "$12}'`)

	cal_sirq $exist_sirq_tool 1

	if [ -f $TOOLS_ROOT/taskstate ]; then
		$TOOLS_ROOT/taskstate -r $rtaskfile -d $dtaskfile -c $taskcountfile
	fi

	running_dump
	uninterrupt_dump
	usr_util=${cpu_util[0]}
	sys_util=${cpu_util[1]}
	io_wait=${cpu_util[2]}
	irq_util=${cpu_util[3]}
	soft_util=${cpu_util[4]}
	cpu_idle=${cpu_util[5]}

	echo "cpu: ${cpu_util[@]}" >> $tmpfile
	if [ $(echo "$load < 1" | bc) -eq 1 ] ;then
		echo "load reason: not high" >> $tmpfile
		detail_result=0

	fi
	if [ $(echo "$usr_util > ((100-$cpu_idle)*0.4)" | bc) -eq 1 ]; then
		high_cost="user "
	fi
	if [ $(echo "$sys_util > ((100-$cpu_idle)*0.2)" | bc) -eq 1 ]; then
		high_cost+="sys "
		extra_cmd="[sysmonitor]"
		extra_info="high memory or kernel competition "
		if [ "$is_cpuflamegraph" != "true" ];then
			if [ -f  $TOOLS_ROOT/cpu_flamegraph ]; then
				$TOOLS_ROOT/cpu_flamegraph -d 5
			fi
		fi
	fi
	if [ $(echo "$irq_util > ((100-$cpu_idle)*0.05)" | bc) -eq 1 ]; then
		high_cost+="irq "
		extra_cmd+="[cpuirq]"
		if [ -f $TOOLS_ROOT/cpuirq ]; then
			$TOOLS_ROOT/cpuirq
		fi
	fi
	if [ $(echo "$soft_util > ((100-$cpu_idle)*0.05)" | bc) -eq 1 ]; then
		high_cost+="softirq "
		extra_info+="high network competition "
		high_sirq=1
	fi
	if [ $(echo "$io_wait > ((100-$cpu_idle)*0.1)" | bc) -eq 1 ]; then
		high_wait="io "
		extra_cmd+="[iolantency]"
	fi
	mutex_cnt=`cat $tmpfile | grep mutex | wc -l`
	if [ $mutex_cnt -gt 5 ]; then
		high_wait+="mutex "
		#extra_cmd+="[lockcheck]"
	fi

	echo "-----" >> $tmpfile
	if [ -f $TOOLS_ROOT/taskstate ]; then
		cat $taskcountfile >> $tmpfile
	else
		echo "uninterrupt_cnt: $uninterrupt_cnt" >> $tmpfile
		echo "running_cnt: $running_cnt" >> $tmpfile
	fi
	if [ $detail_result -eq 1 ]; then
		if [ $(echo "$load*0.2 > $uninterrupt_cnt" | bc) -eq 1 ]; then
			echo "load reason: high $high_cost cpu cost" >> $tmpfile
		else
			if [ $(echo "$load*0.6 < $uninterrupt_cnt" | bc) -eq 1 ]; then
				echo "load reason: high $high_wait wait" >> $tmpfile
			else
				echo "load reason: mixed press by high $high_cost and $high_wait wait" >> $tmpfile
			fi
		fi

		if [ $high_sirq -eq 1 ]; then
			cal_sirq_speed $exist_sirq_tool
		fi

		if [ -n "$extra_info" ]; then
			echo this may caused by $extra_info, you can contact kernel support of use more sysak$extra_cmd tools >> $tmpfile
		fi
	fi

	echo >> $tmpfile
	echo "####################################################################################" >> $tmpfile
	cat ${tmp_cpuflamegraph} >> $tmpfile
	rm ${tmp_cpuflamegraph}
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
		show_result $tmpfile
	fi

	cat ${tmpfile} >> ${datafile}
}

monitor() {
	while :;
	do
		load=`cat /proc/loadavg | awk '{print $1}' | awk -F. '{print $1}'`
		if [ $load -gt $max_load ]; then
			current_analyse

			if [ "$summary" == "true" ];then
				show_result $tmpfile
			fi

			cat ${tmpfile} >> ${datafile}

			if [ "$deamon" != "true" ];then
				exit
			fi
		fi

		sleep $interval
	done
}

mk_log_dir() {
	if [ ! -d "$loadtask_dir" ];then
		mkdir -p $loadtask_dir
	fi
}

kill_old_loadtask() {
	if [ -f "$pidfile" ]; then
		local oldpid=`cat $pidfile`
		local oldtaskname="`cat /proc/$oldpid/status 2>/dev/null | grep -w "Name" | awk -F" " '{print $2}'`"

		if [ "$oldtaskname" == "$selftaskname" ]; then
			kill -9 $oldpid
		fi

		rm -f $pidfile
	fi
}

create_pidfile() {
	echo $$ > $pidfile
}

parse_datafile() {
	if [ -f "$parsed_datafile" ]; then
		local line_arr=(`grep -n "#####" ${parsed_datafile} | awk -F":"  '{print $1}'`)
		local cnt=${#line_arr[@]}
		local i=0

		while [ $i -lt $cnt ]; do
			local start=${line_arr[$i]}

			if [ $i -eq $(($cnt-1)) ]; then
				sed -n ${start}',$p' ${parsed_datafile} > $tmp_parsed_datafile
			else
				local end=$((${line_arr[$i+1]}-1))
				sed -n ${start}','${end}'p' ${parsed_datafile} > $tmp_parsed_datafile
			fi

			head -n 2 $tmp_parsed_datafile
			show_result $tmp_parsed_datafile

			let i=i+1
		done
	fi
}

interval=5
is_cpuflamegraph=false
loadtask_dir=/var/log/sysak/loadtask/
datafile=${loadtask_dir}loadtask-`date "+%Y-%m-%d-%H-%M-%S"`.log
global_cpuflamegraph=${loadtask_dir}global_cpuflamegraph-`date "+%Y-%m-%d-%H-%M-%S"`.svg
tmp_cpuflamegraph=${loadtask_dir}.tmp.svg
tmpfile=${loadtask_dir}.tmplog
rtaskfile=${loadtask_dir}runtask
taskcountfile=${loadtask_dir}taskcount
dtaskfile=${loadtask_dir}dtask
tmpsirqfile=${loadtask_dir}tmpsoftirq
sirqspeedfile=${loadtask_dir}softirqspeed
pidfile=${loadtask_dir}.pidfile
detail_result=1
max_load=0
sirq_num=$((`cat /proc/softirqs | wc -l`-1))
sirq_before=()
sirq_after=()
selftaskname="`cat /proc/$$/status | grep -w "Name" | awk -F" " '{print $2}'`"
parsed_datafile=""
tmp_parsed_datafile=${loadtask_dir}.parsedlog

while getopts 'm:f:i:t:r:dskgh' OPT; do
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
		"k")
			kill_old_loadtask
			exit 0
			;;
		"s")
			summary="true"
			;;
		"r")
			parsed_datafile=$OPTARG
			mk_log_dir
			parse_datafile
			exit 0
			;;
		"g")
			is_cpuflamegraph="true"
			;;
		*)
			usage
			exit -1
		;;
	esac
done

mk_log_dir
kill_old_loadtask
create_pidfile

if [ $max_load -gt 0 ];then
	monitor
else
	load_analyse
fi
