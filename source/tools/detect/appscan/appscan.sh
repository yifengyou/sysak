#!/bin/sh

pid=-1

CURDATE=$(date "+%Y-%m-%d-%H-%M-%S")
SLOGDIR="/var/log/sysak"
WORKDIR="$(hostname)_appscan"
LOGDIR="${SLOGDIR}/${WORKDIR}"
LOGFILE=""
CPU_RESFILE="scan_cpu_result"
MEM_RESFILE="scan_mem_result"
IO_RESFILE="scan_io_result"
PERFDIR=""
CURPATH="$SYSAK_WORK_PATH/tools"

SCAN_CPU_PID=-1
SCAN_MEM_PID=-1
SCAN_IO_PID=-1
SCAN_NET_PID=-1
SCAN_TIME=-1

#############################CPU result#############################
SCAN_CPU_SUM=0
THEAD_ID_ARR=()
CPU_LOW_CNT_ARR=()
CPU_SYS_HIGH_CNT_ARR=()
CSWCH_HIGH_ARR=()
NVCSWCH_HIGH_ARR=()
CSWCH_SUM_ARR=()
CPU_SCAN_SUM_ARR=()

############################Memory result############################
SCAN_MEM_SUM=0
MEM_MINOR_PF_CNT=0
MEM_MAJOR_PF_CNT=0
MEM_LOW_WM_CNT=0
MEM_HIGH_WM_CNT=0
MEM_DIFF_NUMA_FLAG=0
MEM_THREAD_RUN_DIFF_NUMA_FLAG=0

##############################IO result##############################
SCAN_IO_SUM=0
IO_BUSY_CNT=0

##############################threshold##############################
CPU_RATIO_LOW_LVL=50  #20
CPU_RATIO_LOW_SYS_LVL=$((CPU_RATIO_LOW_LVL/3))
CPU_RATIO_HIGH_SYS_LVL=20
PERF_LAST_TIME=3

THREAD_CSWCH_HIGH_LVL=100
THREAD_NVCSWCH_HIGH_LVL=200

PROCESS_MINOR_PG_FAULT_LVL=50
PROCESS_MAJOR_PG_FAULT_LVL=0

IO_QUEUE_SIZE_LVL=20.00

IO_AWAIT_LVL=3.00
IO_SVCTM_LVL=1.00
IO_AWAIT_SVC_MUL_LVL=5
##############################threshold##############################

function usage() {
	echo "sysak appscan: Scan process for performance bottlenecks"
	echo "options: -h, help information"
	echo "         -p pid, process id to be monitored"
	echo "         -t seconds, scan duration(unit is second).If not specified, stop when a bottleneck is detected"
}

function add_cpu_sched_arr_cnt() {
	local arr_num=${#THEAD_ID_ARR[@]}
	local i=0
	local flag=0

	while [ $i -lt $arr_num ]; do
		if [ ${THEAD_ID_ARR[$i]} -eq $1 ]; then
			if [ $2 -eq 1 ]; then
				let CPU_LOW_CNT_ARR[$i]=CPU_LOW_CNT_ARR[$i]+1
			elif [ $2 -eq 2 ]; then
				let CPU_SYS_HIGH_CNT_ARR[$i]=CPU_SYS_HIGH_CNT_ARR[$i]+1
			elif [ $2 -eq 3 ]; then
				let CSWCH_HIGH_ARR[$i]=CSWCH_HIGH_ARR[$i]+1
			elif [ $2 -eq 4 ]; then
				let NVCSWCH_HIGH_ARR[$i]=NVCSWCH_HIGH_ARR[$i]+1
			elif [ $2 -eq 5 ]; then
				let CSWCH_SUM_ARR[$i]=CSWCH_SUM_ARR[$i]+1
			elif [ $2 -eq 6 ]; then
				let CPU_SCAN_SUM_ARR[$i]=CPU_SCAN_SUM_ARR[$i]+1
			else
				echo "function parameter error">>${LOGFILE}
			fi

			flag=1
			break
		fi

		let i=i+1
	done

	if [ $flag -eq 0 ]; then
		THEAD_ID_ARR[arr_num]=$1

		if [ $2 -eq 1 ]; then
			###cpu low###
			CPU_LOW_CNT_ARR[arr_num]=1
			CPU_SYS_HIGH_CNT_ARR[arr_num]=0
			CSWCH_HIGH_ARR[arr_num]=0
			NVCSWCH_HIGH_ARR[arr_num]=0
			CSWCH_SUM_ARR[arr_num]=0
			CPU_SCAN_SUM_ARR[arr_num]=0
		elif [ $2 -eq 2 ]; then
			###cpu sys high###
			CPU_LOW_CNT_ARR[arr_num]=0
			CPU_SYS_HIGH_CNT_ARR[arr_num]=1
			CSWCH_HIGH_ARR[arr_num]=0
			NVCSWCH_HIGH_ARR[arr_num]=0
			CSWCH_SUM_ARR[arr_num]=0
			CPU_SCAN_SUM_ARR[arr_num]=0
		elif [ $2 -eq 3 ]; then
			###voluntary context switch###
			CPU_LOW_CNT_ARR[arr_num]=0
			CPU_SYS_HIGH_CNT_ARR[arr_num]=0
			CSWCH_HIGH_ARR[arr_num]=1
			NVCSWCH_HIGH_ARR[arr_num]=0
			CSWCH_SUM_ARR[arr_num]=0
			CPU_SCAN_SUM_ARR[arr_num]=0
		elif [ $2 -eq 4 ]; then
			###involuntary context switch###
			CPU_LOW_CNT_ARR[arr_num]=0
			CPU_SYS_HIGH_CNT_ARR[arr_num]=0
			CSWCH_HIGH_ARR[arr_num]=0
			NVCSWCH_HIGH_ARR[arr_num]=1
			CSWCH_SUM_ARR[arr_num]=0
			CPU_SCAN_SUM_ARR[arr_num]=0
		elif [ $2 -eq 5 ]; then
			###Number of scan thread context switches###
			CPU_LOW_CNT_ARR[arr_num]=0
			CPU_SYS_HIGH_CNT_ARR[arr_num]=0
			CSWCH_HIGH_ARR[arr_num]=0
			NVCSWCH_HIGH_ARR[arr_num]=0
			CSWCH_SUM_ARR[arr_num]=1
			CPU_SCAN_SUM_ARR[arr_num]=0
		elif [ $2 -eq 6 ]; then
			###Number of scan cpu###
			CPU_LOW_CNT_ARR[arr_num]=0
			CPU_SYS_HIGH_CNT_ARR[arr_num]=0
			CSWCH_HIGH_ARR[arr_num]=0
			NVCSWCH_HIGH_ARR[arr_num]=0
			CSWCH_SUM_ARR[arr_num]=0
			CPU_SCAN_SUM_ARR[arr_num]=1
		else
			echo "function parameter error">>${LOGFILE}
		fi
	fi

:<<!
	echo -n "        Thread id:"
	for i in ${THEAD_ID_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo  THEAD_ID_ARR num:${#THEAD_ID_ARR[@]}

	echo -n "      CPU low cnt:"
	for i in ${CPU_LOW_CNT_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo -n " CPU sys high cnt:"
	for i in ${CPU_SYS_HIGH_CNT_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo -n "  cswch high cnt:"
	for i in ${CSWCH_HIGH_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo -n "nvcswch high cnt:"
	for i in ${NVCSWCH_HIGH_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo -n "   cswch sum cnt:"
	for i in ${CSWCH_SUM_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo -n "cpu scan sum cnt:"
	for i in ${CPU_SCAN_SUM_ARR[*]}; do
		echo -n $i
	done
	echo " "

	echo " "
!
}

function add_cpu_low_cnt() {
	add_cpu_sched_arr_cnt $1 1
}

function add_cpu_sys_high_cnt() {
	add_cpu_sched_arr_cnt $1 2
}

function add_cswch_high_cnt() {
	add_cpu_sched_arr_cnt $1 3
}

function add_nvcswch_high_cnt() {
	add_cpu_sched_arr_cnt $1 4
}

function add_cswch_sum_cnt() {
	add_cpu_sched_arr_cnt $1 5
}

function add_cpu_scan_sum_cnt() {
	add_cpu_sched_arr_cnt $1 6
}

function perf_fun() {
	perf_cmd=$1
	`$perf_cmd >/dev/null 2>&1`
}

function scan_cpu() {
	trap 'on_cpu_abrt' SIGABRT
	trap "" SIGINT

	while : ;do
	    local cmd_res=`pidstat -t -u -w -p $pid 1 1 2>/dev/null | grep -E "Average|平均时间" | grep -v "UID"`

		local row_num=`echo "$cmd_res" | wc -l`
		row_num=$((row_num/2))
		local cpu_ratio=(`echo "$cmd_res" | head -n $row_num | awk '{print $4,$5,$6,$8}' | sed "s/\.[0-9]*//g"`)

		local ctx_swch=(`echo "$cmd_res" | tail -n $row_num | awk '{print $4,$5,$6}' | sed "s/\.[0-9]*//g"`)
		local cpu_ratio_num=${#cpu_ratio[@]}
		local bg_pid=-1

		local i=0
		local j=0

		while [ $i -lt $cpu_ratio_num ]; do
			tid=${cpu_ratio[$i]}
			usr=${cpu_ratio[$i+1]}
			sys=${cpu_ratio[$i+2]}
			sum=${cpu_ratio[$i+3]}

			if [ $i -eq 0 ]; then
				let i=i+4
				let j=j+3
				continue
			else
				perf_cmd="perf record -g --tid=$tid"
				task_name="thread $tid"
			fi

			add_cpu_scan_sum_cnt $tid

			if [ $sum -lt $CPU_RATIO_LOW_LVL ]; then
				#CPU usage too low
				add_cpu_low_cnt $tid

				echo "$task_name cpu usage $sum is lower than $CPU_RATIO_LOW_LVL" >>${LOGFILE}

				perf_cmd="${perf_cmd} -o ${PERFDIR}/perf.tid_${tid}-cpu_usage_low_$sum.`date "+%Y-%m-%d-%H-%M-%S"`.data sleep ${PERF_LAST_TIME}"

				if [ $sys -gt $CPU_RATIO_LOW_SYS_LVL ]; then
					############sys too high,perf the thread###########################
					echo "$task_name cpu sys usage $sys is higher than $CPU_RATIO_LOW_SYS_LVL" >>${LOGFILE}
				else
					############usr triggers schedule,like mutex and so on.############
					echo "Maybe $task_name triggers schedule too frequently, like Mutex granularity is too large and so on." >>${LOGFILE}
				fi

				echo "$perf_cmd" >>${LOGFILE}
				#`$perf_cmd >/dev/null 2>&1` &
				perf_fun "$perf_cmd" &
				bg_pid=$!
			else
				#CPU usage high

				if [ $sys -gt $CPU_RATIO_HIGH_SYS_LVL ]; then
					########################CPU sys usage high####################
					add_cpu_sys_high_cnt $tid
					echo "$task_name cpu sys usage $sys is higher than $CPU_RATIO_HIGH_SYS_LVL" >>${LOGFILE}

					perf_cmd="${perf_cmd} -o ${PERFDIR}/perf.tid_${tid}-cpu_sys_high_$sys.`date "+%Y-%m-%d-%H-%M-%S"`.data sleep ${PERF_LAST_TIME}"

					echo "$perf_cmd" >>${LOGFILE}
					perf_fun "$perf_cmd" &
					bg_pid=$!
				else
					########################CPU usr usage high###################
					cswch=${ctx_swch[$j+1]}
					nvcswch=${ctx_swch[$j+2]}

					############################check context switch frequency##################################
					add_cswch_sum_cnt $tid

					if [ $cswch -gt $THREAD_CSWCH_HIGH_LVL ]; then
						add_cswch_high_cnt $tid
						echo "thread $tid voluntary context switch frequency $cswch greater than $THREAD_CSWCH_HIGH_LVL/s" >>${LOGFILE}
					fi

					if [ $nvcswch -gt $THREAD_NVCSWCH_HIGH_LVL ]; then
						add_nvcswch_high_cnt $tid
						echo "thread $tid involuntary context switch frequency $nvcswch greater than $THREAD_NVCSWCH_HIGH_LVL/s" >>${LOGFILE}
					fi

					############################check if bind cpu core or not###################################
					cpu_on_line=`lscpu | grep On-line | awk '{print $4}'`
					cpu_allowed=`cat /proc/$tid/status | grep "Cpus_allowed_list" | awk '{print $2}'`

					if [ "$cpu_allowed" != "$cpu_on_line" ]; then
						echo "thread $tid bind cpu $cpu_allowed" >>${LOGFILE}
					fi
				fi
			fi

			let i=i+4
			let j=j+3
		done

		if [ $bg_pid -gt 0 ]; then
			wait $bg_pid
		fi
		
	done	
}

function scan_mem() {
	local low_wmark_hit=-1
	local high_wmark_hit=-1

	trap 'on_mem_abrt' SIGABRT
	trap "" SIGINT

	while : ;do
		##########################check process page fault############################
		local pg_fault=(`pidstat -r -p $pid 2 1 2>/dev/null | tail -n 1 | awk '{print $4,$5}' | sed "s/\.[0-9]*//g"`)
    	
		local minor_fault=${pg_fault[0]}
		local major_fault=${pg_fault[1]}

		let SCAN_MEM_SUM=SCAN_MEM_SUM+1

    	if [ $minor_fault -gt $PROCESS_MINOR_PG_FAULT_LVL ]; then
			echo "process $pid minor page fault $minor_fault is greater than $PROCESS_MINOR_PG_FAULT_LVL" >>${LOGFILE}
			let MEM_MINOR_PF_CNT=MEM_MINOR_PF_CNT+1
    	fi
    
    	if [ $major_fault -gt $PROCESS_MAJOR_PG_FAULT_LVL ]; then
			echo "process $pid major page fault $major_fault is greater than $PROCESS_MAJOR_PG_FAULT_LVL" >>${LOGFILE}
			let MEM_MAJOR_PF_CNT=MEM_MAJOR_PF_CNT+1
    	fi
    
        #############################check watermark###################################
		local node_info=(`cat /proc/zoneinfo | grep -A 3 "pages free" | tr -cd "[0-9]\n"`)
		local node_name=`cat /proc/zoneinfo | grep Node`
    
		local i=0
		local j=1
		local node_info_num=${#node_info[@]}
    
    	while [ $i -lt $node_info_num ]; do
			local free=${node_info[$i]}
			local min=${node_info[$i+1]}
			local low=${node_info[$i+2]}
			local high=${node_info[$i+3]}
    
    		if [ $free -lt $high ]; then
				echo "`echo "$node_name" |  sed -n ${j}'p'` free memory $free is lower than watermark $high pages" >>${LOGFILE}
    		fi	
    
    		let i=i+4
    		let j=j+1
    	done
    
		############################check watermark hit################################
		local wmark_hit=(`cat /proc/vmstat | grep  "kswapd_.*_wmark_hit_quickly" | awk '{print $2}'`)
		local tmp_low_wmark_hit=${wmark_hit[0]}
		local tmp_high_wmark_hit=${wmark_hit[1]}

		if [ $low_wmark_hit -ne -1 ]; then
			let low_diff=tmp_low_wmark_hit-low_wmark_hit
			let high_diff=tmp_high_wmark_hit-high_wmark_hit

			if [ $low_diff -gt 0 ]; then
				echo "The number of free pages drops below the low watermark $low_diff timers in a second." >>${LOGFILE}
				let MEM_LOW_WM_CNT=MEM_LOW_WM_CNT+1
			fi

			if [ $high_diff -gt 0 ]; then
				echo "The number of free pages drops below the high watermark $high_diff times in a second." >>${LOGFILE}
				let MEM_HIGH_WM_CNT=MEM_HIGH_WM_CNT+1
			fi
		fi

		low_wmark_hit=$tmp_low_wmark_hit
		high_wmark_hit=$tmp_high_wmark_hit	

		###########################check NUMA#########################################
		local numa_info=(`numastat -p $pid 2>/dev/null | tail -n 1 | awk  '{for (i=2;i<NF;i++) print $i}'`)

		j=0
		local node_id=-1
		for i in ${numa_info[@]}; do
			if [ "$i" != "0.00" ]; then
				let j=j+1
			fi

			let node_id=node_id+1
		done
		
		if [ $j -ne 1 ]; then
			#Memroy locate in different NUMA node
			echo "Process $pid memory locate different NUMA node." >>${LOGFILE}
			MEM_DIFF_NUMA_FLAG=1
		else
			#Memory locate in same NUMA node.Check threads if running on the NUMA node which memory locates or not.
			local node_cpus=(`numactl --hardware 2>/dev/null | grep "node $node_id cpus" | awk -F":" '{print $2}'`)
		
			local running_threads=(`pidstat -t -p $pid | grep -v "CPU" | awk '{print $5,$10}'`)
			local running_threads_num=${#running_threads[@]}

			i=2
			while [ $i -lt $running_threads_num ]; do
				local thread_id=${running_threads[$i]}
				local thread_cpu=${running_threads[$i+1]}
				local flag=0

				for j in ${node_cpus[@]}; do
					if [ $thread_cpu -eq $j ]; then
						flag=1
						break
					fi
				done

				if [ $flag -eq 0 ]; then
					echo "Thread $thread_id running not in NUMA node $node_id" >>${LOGFILE}
					MEM_THREAD_RUN_DIFF_NUMA_FLAG=1
				fi

				let i=i+2
			done
		fi
    done
}

function scan_io() {
	trap 'on_io_abrt' SIGABRT
	trap "" SIGINT

	while :; do
		if [ ! -d "/proc/sysak/appscan" ];then
			echo "directory /proc/sysak/appscan not exists" >> ${LOGFILE}
			sleep 5
		else
			break
		fi
	done

	echo 1 > /proc/sysak/appscan/enable

	while :; do
		#local io_info=(`iostat -y -x 1 1 | grep -A 1000 "Device" | grep -v "Device" | awk '{print $1,$9,$10,$11,$12,$13,$14}' | sed "s/\.[0-9]*//g"`)
		echo $pid > /proc/sysak/appscan/pid
		local io_info=(`iostat -y -x 1 1 | grep -A 1000 "Device" | grep -v "Device" | awk '{print $1,$6,$7,$8,$9,$10,$11,$12,$13,$14}'`)

		local pid_devs=(`cat /proc/sysak/appscan/dev`)

		echo -1 > /proc/sysak/appscan/pid

		let SCAN_IO_SUM=SCAN_IO_SUM+1

:<<!
		for i in ${pid_devs[@]}
		do
			echo pid_devs:$i
		done
!

		local io_info_num=${#io_info[@]}
		local io_devs=()
		local i=0
		local flag=0

		while [ $i -lt $io_info_num ]; do
			local dev=${io_info[$i]}
			local read=${io_info[$i+1]}
			local write=${io_info[$i+2]}
			local rq_sz=${io_info[$i+3]}
			local queue_sz=${io_info[$i+4]}
			local await=${io_info[$i+5]}
			local rawait=${io_info[$i+6]}
			local wawait=${io_info[$i+7]}
			local svctm=${io_info[$i+8]}
			local util=${io_info[$i+9]}

			local alert_info="alert device[$dev] read[${read}kB/s] write[${write}kB/s] avgrq-sz[$rq_sz] avgqu-sz[$queue_sz] await[${await}ms] r_await[${rawait}ms] w_await[${wawait}ms] svctm[${svctm}ms] %util[$util]:\n"

			flag=0

			if [ `echo "$await > $IO_AWAIT_LVL"|bc` -eq 1 ]; then
				echo -e "${alert_info}await is greater than ${IO_AWAIT_LVL}ms" >>${LOGFILE}
				alert_info=""
				flag=1
			elif [ `echo "$rawait > $IO_AWAIT_LVL"|bc` -eq 1 ]; then
				echo -e "${alert_info}rawait is greater than ${IO_AWAIT_LVL}ms" >>${LOGFILE}
				alert_info=""
				flag=1
			elif [ `echo "$wawait > $IO_AWAIT_LVL"|bc` -eq 1 ]; then
				echo -e "${alert_info}wawait is greater than ${IO_AWAIT_LVL}ms" >>${LOGFILE}
				alert_info=""
				flag=1
			fi

			if [ `echo "$svctm > $IO_SVCTM_LVL"|bc` -eq 1 ]; then
				echo -e "${alert_info}svctm is greater than ${IO_SVCTM_LVL}ms" >>${LOGFILE}
				flag=1
			fi

			if [ $flag -eq 0 ] && [ `echo "$svctm > 0"|bc` -eq 1 ]; then
				if [ `echo "${await}/${svctm}"|bc` -gt $IO_AWAIT_SVC_MUL_LVL ]; then
					echo -e "${alert_info}await/svctm is greater than $IO_AWAIT_SVC_MUL_LVL" >>${LOGFILE}
					alert_info=""
					flag=1
				elif [ `echo "${rawait}/${svctm}"|bc` -gt $IO_AWAIT_SVC_MUL_LVL ]; then
					echo -e "${alert_info}r_await/svctm is greater than $IO_AWAIT_SVC_MUL_LVL" >>${LOGFILE}
					alert_info=""
					flag=1
				elif [ `echo "${wawait}/${svctm}"|bc` -gt $IO_AWAIT_SVC_MUL_LVL ]; then
					echo -e "${alert_info}w_await/svctm is greater than $IO_AWAIT_SVC_MUL_LVL" >>${LOGFILE}
					alert_info=""
					flag=1
				fi
			fi

			if [ $flag -eq 1 ]; then
				io_devs+=($dev)
			fi

			let i=i+10
		done

		flag=0
		for i in ${io_devs[@]}; do
			for j in ${pid_devs[@]}; do
				if [ "$i" = "$j" ]; then
					flag=1
					echo "Process $pid has IO from/to device ${i} which is very busy!" >>${LOGFILE}
				fi
			done
		done

		if [ $flag -eq 1 ]; then
			let IO_BUSY_CNT=IO_BUSY_CNT+1
		fi

	done
}

function scan_net() {
	echo "scan net"
}

function write_scan_cpu_res() {
	local i=0
	local flag=0
	local arr_num=0

	printf "#########################CPU & Schedule#########################\n" >> $CPU_RESFILE

	i=0
	arr_num=${#CPU_LOW_CNT_ARR[*]}

	while [ $i -lt $arr_num ]; do
		if [ ${CPU_LOW_CNT_ARR[$i]} -gt 0 ]; then
			if [ $flag -eq 0 ]; then
				printf "CPU usage lower than ${CPU_RATIO_LOW_LVL}%% are threads:\n" >> $CPU_RESFILE
				printf "%-15s%-25s%-35s\n" "Thread id" "Number of occurrences" "Total number of scanning" >> $CPU_RESFILE
			fi

			flag=1
			printf "%-23d%-25d%-35d\n" ${THEAD_ID_ARR[$i]} ${CPU_LOW_CNT_ARR[$i]} ${CPU_SCAN_SUM_ARR[$i]} >> $CPU_RESFILE
		fi

		let i=i+1
	done

	i=0
	flag=0
	arr_num=${#CPU_SYS_HIGH_CNT_ARR[*]}

	while [ $i -lt $arr_num ]; do
		if [ ${CPU_SYS_HIGH_CNT_ARR[$i]} -gt 0 ]; then
			if [ $flag -eq 0 ]; then
				printf "\nCPU sys usage higher than ${CPU_RATIO_HIGH_SYS_LVL}%% are threads:\n" >> $CPU_RESFILE
				printf "%-15s%-25s%-35s\n" "Thread id" "Number of occurrences" "Total number of scanning" >> $CPU_RESFILE
			fi

			flag=1
			printf "%-23d%-25d%-35d\n" ${THEAD_ID_ARR[$i]} ${CPU_SYS_HIGH_CNT_ARR[$i]} ${CPU_SCAN_SUM_ARR[$i]} >> $CPU_RESFILE
		fi

		let i=i+1
	done

	i=0
	flag=0
	arr_num=${#CSWCH_HIGH_ARR[*]}

	while [ $i -lt $arr_num ]; do
		if [ ${CSWCH_HIGH_ARR[$i]} -gt 0 ]; then
			if [ $flag -eq 0 ]; then
				printf "\nWhen cpu usage is normal, but voluntary context switch frequency higher than ${THREAD_CSWCH_HIGH_LVL} counts per second are threads:\n" >> $CPU_RESFILE
				printf "%-15s%-25s%-35s\n" "Thread id" "Number of occurrences" "Total number of scanning" >> $CPU_RESFILE
			fi

			flag=1
			printf "%-23d%-25d%-35d\n" ${THEAD_ID_ARR[$i]} ${CSWCH_HIGH_ARR[$i]} ${CSWCH_SUM_ARR[$i]} >> $CPU_RESFILE
		fi

		let i=i+1
	done

	i=0
	flag=0
	arr_num=${#NVCSWCH_HIGH_ARR[*]}

	while [ $i -lt $arr_num ]; do
		if [ ${NVCSWCH_HIGH_ARR[$i]} -gt 0 ]; then
			if [ $flag -eq 0 ]; then
				printf "\nWhen cpu usage is normal, but involuntary context switch frequency higher than ${THREAD_NVCSWCH_HIGH_LVL} counts per second are threads:\n" >> $CPU_RESFILE
				printf "%-15s%-25s%-35s\n" "Thread id" "Number of occurrences" "Total number of scanning" >> $CPU_RESFILE
			fi

			flag=1
			printf "%-23d%-25d%-35d\n" ${THEAD_ID_ARR[$i]} ${NVCSWCH_HIGH_ARR[$i]} ${CSWCH_SUM_ARR[$i]} >> $CPU_RESFILE
		fi

		let i=i+1
	done
}

function write_scan_mem_res() {
	printf "#############################Memory#############################\n" >> $MEM_RESFILE

	if [ $MEM_MINOR_PF_CNT -gt 0 ]; then
		printf "Process minor page fault is greater than $PROCESS_MINOR_PG_FAULT_LVL per second:\n" >> $MEM_RESFILE
		printf "%-25s%-35s\n" "Number of occurrences" "Total number of scanning" >> $MEM_RESFILE
		printf "%-35d%-35d\n" ${MEM_MINOR_PF_CNT} ${SCAN_MEM_SUM} >> $MEM_RESFILE
	fi

	if [ $MEM_MAJOR_PF_CNT -gt 0 ]; then
		printf "Process major page fault is greater than $PROCESS_MAJOR_PG_FAULT_LVL per second:\n" >> $MEM_RESFILE
		printf "%-25s%-35s\n" "Number of occurrences" "Total number of scanning" >> $MEM_RESFILE
		printf "%-35d%-35d\n" ${MEM_MAJOR_PF_CNT} ${SCAN_MEM_SUM} >> $MEM_RESFILE
	fi

	if [ $MEM_LOW_WM_CNT -gt 0 ]; then
		printf "The number of free pages drops below the low watermark in a second:\n" >> $MEM_RESFILE
		printf "%-25s%-35s\n" "Number of occurrences" "Total number of scanning" >> $MEM_RESFILE
		printf "%-35d%-35d\n" ${MEM_LOW_WM_CNT} ${SCAN_MEM_SUM} >> $MEM_RESFILE
	fi

	if [ $MEM_HIGH_WM_CNT -gt 0 ]; then
		printf "The number of free pages drops below the high watermark in a second:\n" >> $MEM_RESFILE	
		printf "%-25s%-35s\n" "Number of occurrences" "Total number of scanning" >> $MEM_RESFILE
		printf "%-35d%-35d\n" ${MEM_HIGH_WM_CNT} ${SCAN_MEM_SUM} >> $MEM_RESFILE
	fi

	if [ $MEM_DIFF_NUMA_FLAG -eq 1 ]; then
		printf "\nProcess memory locate different NUMA node.\n" >> $MEM_RESFILE
	fi

	if [ $MEM_THREAD_RUN_DIFF_NUMA_FLAG -eq 1 ]; then
		printf "\nThread of process run different NUMA node.\n" >> $MEM_RESFILE
	fi
}

function write_scan_io_res() {
	printf "###############################IO###############################\n" >> $IO_RESFILE

	if [ $IO_BUSY_CNT -gt 0 ]; then
		printf "Process has IO from/to device(s) which is(are) very busy:\n" >> $IO_RESFILE
		printf "%-25s%-35s\n" "Number of occurrences" "Total number of scanning" >> $IO_RESFILE
		printf "%-35d%-35d\n" ${IO_BUSY_CNT} ${SCAN_IO_SUM} >> $IO_RESFILE
	fi
}

function on_cpu_abrt() {
	write_scan_cpu_res
	exit
}

function on_mem_abrt() {
	write_scan_mem_res
	exit
}

function on_io_abrt() {
	echo 0 > /proc/sysak/appscan/enable
	write_scan_io_res
	exit
}

function on_ctrl_c() {
	kill_scan_process
	#wait
	show_scan_res
	exit
}

function show_scan_res() {
	cat ${CPU_RESFILE}
	echo ""
	cat ${MEM_RESFILE}
	echo ""
	cat ${IO_RESFILE}
}

function check_opts() {
	if [ $pid -eq -1 ]; then
		usage
		exit -1
	fi
}

function mk_log_dir() {
	if [ ! -d "$LOGDIR" ];then
		mkdir -p $LOGDIR
	fi

	LOGDIR="${LOGDIR}/pid_$pid.${CURDATE}"
	PERFDIR="${LOGDIR}/perf"
	LOGFILE="${LOGDIR}/log"
	CPU_RESFILE="${LOGDIR}/${CPU_RESFILE}"
	MEM_RESFILE="${LOGDIR}/${MEM_RESFILE}"
	IO_RESFILE="${LOGDIR}/${IO_RESFILE}"

	if [ ! -d "$LOGDIR" ];then
		echo "Create directory $LOGDIR for saving log and perf data."
		mkdir $LOGDIR
		mkdir $PERFDIR
	else
		echo "directory $LOGDIR already exists"
		exit -1
	fi
}

function kill_scan_process() {
	kill -s 6 $SCAN_CPU_PID
	kill -s 6 $SCAN_MEM_PID
	kill -s 6 $SCAN_IO_PID
#	kill $SCAN_NET_PID
	wait
}

while getopts 'p:t:lh' OPT; do
    case $OPT in
        "h")
            usage
            exit 0
            ;;
        "p")
            pid=$OPTARG
            ;;
        "t")
            SCAN_TIME=$OPTARG
            ;;
        *)
            usage
            exit -1
        ;;
    esac
done

check_opts
mk_log_dir

scan_cpu &
SCAN_CPU_PID=$!

scan_mem &
SCAN_MEM_PID=$!

scan_io &
SCAN_IO_PID=$!

#scan_net &
#SCAN_NET_PID=$!

#echo "cpu_pid:${SCAN_CPU_PID} mem_pid:${SCAN_MEM_PID} io_pid:${SCAN_IO_PID}"

trap 'on_ctrl_c' INT

if [ $SCAN_TIME -ne -1 ]; then
	sleep $SCAN_TIME
	kill_scan_process
	show_scan_res
else
	wait
fi

