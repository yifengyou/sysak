#!/bin/bash

memcg_dir="/sys/fs/cgroup/memory"
interval=10
times=5
unit=1
tmp_dir="memcgshow_tmp"

# arguments
usage()
{
	echo "memcg_show: statistics of usage,rss,cache... of each memcg"
	echo "Usage:"
	echo "  sysak cgtool memcg_show [OPTION...] "
	echo "    -h, help information"
	echo "    -i, detection time interval, default: ${interval}s"
	echo "    -t, detection times, default: ${times} times"
	echo "    -u, [B/KB/MB/G], default: MB"
	echo "    -d, memcg dir, default: $memcg_dir"
	echo "    "
	echo "Examples:"
	echo "  sysak cgtool memcg_show"
	echo "  sysak cgtool memcg_show -i 60 -t 10 -u G"
}

memstat()
{
	local stat_dir=$1
	local result_file=$2

	local usage=`cat $stat_dir/memory.usage_in_bytes`
	local memswusage=`cat $stat_dir/memory.memsw.usage_in_bytes`
	local kmemusage=`cat $stat_dir/memory.kmem.usage_in_bytes`
	local total_cache=`cat $stat_dir/memory.stat |grep total_cache |awk -F" " '{print $2}'`
	local total_rss=`cat $stat_dir/memory.stat |grep total_rss |sed -n 1p |awk -F" " '{print $2}'`
	local total_swap=`cat $stat_dir/memory.stat |grep total_swap |sed -n 1p |awk -F" " '{print $2}'`
	local real_use=$(($total_cache + $total_rss + $total_swap))


	# memory.usage_in_bytes = cache + rss
	# real_use = cache + rss + swap
	# memory.memsw.usage_in_bytes = memory.usage_in_bytes + swap
	echo "$stat_dir $usage $total_rss $total_cache $total_swap $real_use $kmemusage $memswusage" >> $result_file
}

memstat_all()
{
	local dir_n=0
	local stat_dir=$1
	local result_file=$2

	for file in `ls $stat_dir`
	do
		if [ -d "$stat_dir/$file" ]; then
			memstat_all $stat_dir/$file $result_file
			dir_n=$(($dir_n + 1))
		fi
	done

	if [ $dir_n -eq 0 ]; then
		memstat $stat_dir $result_file
	fi
}

output()
{
    lines=`cat ${tmp_dir}/0.result | wc -l`
    for ((i=1; i<=$lines; i++))
    do
        echo "=============================================="

        memcg=`cat ${tmp_dir}/0.result | sed -n ${i}p |awk -F" " '{print $1}'`
        echo ${memcg//)/\\\\}
    
        n=2
        for name in usage rss cache swap cache+rss+swap kmemusage memswusage
        do
            out="$name:"
            for ((j=0; j<$times; j++))
            do
    	        data=`cat ${tmp_dir}/${j}.result | grep -w $memcg |awk -F' ' -vx=$n '{print $x}'`
		if [ $? -ne 0 ]; then
		    continue
		fi

		if [ "X$data" != "X0" ]; then
		    data=$(($data/$unit))
		fi

                out="$out $data"
            done
    
            echo $out
    	    n=$(($n+1))
        done

        echo ""
    done
    
    rm -rf $tmp_dir
}

while getopts 'i:t:u:d:h' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"i")
			interval=$OPTARG
			;;
		"t")
			times=$OPTARG
			;;
		"u")
			if [ "X$OPTARG" == "XB" ]; then
				unit=1
			elif [ "X$OPTARG" == "XKB" ]; then
				unit=1024
			elif [ "X$OPTARG" == "XMB" ]; then
				unit=$((1024*1024))
			elif [ "X$OPTARG" == "XG" ]; then
				unit=$((1024*1024*1024))
			else
				echo "Parameter error, -u $OPTARG, expect [B/KB/MB/G]"
				exit 1
			fi
			;;
		"d")
			memcg_dir=$OPTARG
			;;
		*)
			usage
			exit 0
		;;
	esac
done

# collect data
rm -rf $tmp_dir; mkdir -p $tmp_dir
for ((i=0; i<$times; i++))
do
    memstat_all $memcg_dir ${tmp_dir}/${i}.result

    # add \ to change memcg from $memcg_dir/system\x2dpolicy to $memcg_dir/system)x2dpolicy
    sed -e 's:\\:):g' -i ${tmp_dir}/${i}.result

    sleep $interval
done

# output data
output
