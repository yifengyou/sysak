WORK_PATH=`dirname $0`/
pid=-1

runlatency_enable() {
	echo 1 > /proc/sysak/runlatency/irqoff/enable
	echo 1 > /proc/sysak/runlatency/nosch/enable
	echo $pid > /proc/sysak/runlatency/runqlat/pid
}

runlatency_disable() {
	echo 0 > /proc/sysak/runlatency/irqoff/enable
	echo 0 > /proc/sysak/runlatency/nosch/enable
	echo -1 > /proc/sysak/runlatency/runqlat/pid
}

runlatency_report() {
	
	if [ -z "$outfile" ]; then
		$WORK_PATH/rt_json_dump
	else
		$WORK_PATH/rt_json_dump >>$outfile
	fi
}

usage() {
	echo "$0 -e|d"
	echo "   -e, enable"
	echo "   -d, disable"
	echo "   -r, report, default stdout if no outfile specified"
	echo "   -f, outfile for report"
}

while getopts 'p:f:edrh' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"p")
			pid=$OPTARG
			;;
		"e")
			runlatency_enable
			exit 0
			;;
		"d")
			runlatency_disable
			exit 0
			;;
		"r")
			report="true"
			;;
		"f")
			outfile=$OPTARG
			;;
		*)
			echo this
			usage
			exit -1
		;;
	esac
done

if [ $report = "true" ];then
	runlatency_report
fi

