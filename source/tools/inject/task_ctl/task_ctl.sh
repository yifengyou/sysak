WORK_PATH=`dirname $0`

task_ctl_enable() {
	echo "enable" > /proc/sysak_task_ctl
}

task_ctl_disable() {
	echo "disable" > /proc/sysak_task_ctl
}

usage() {
	echo "$0 [opt] -e|d"
	echo "   -e, enable"
	echo "   -d, disable"
	echo "opt:"
	echo "   -p pid"
	echo "   -t type, loop or sleep "
}

while getopts 'p:t:edh' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"p")
			echo "pid $OPTARG" > /proc/sysak_task_ctl
			;;
		"t")
			echo "type $OPTARG" > /proc/sysak_task_ctl
			;;
		"e")
			trace_enable=true
			;;
		"d")
			trace_disable=true;
			;;
		*)
			usage
			exit -1
		;;
	esac
done


if [ $trace_enable ]; then
	task_ctl_enable
fi

if [ $trace_disable ]; then
	task_ctl_disable
fi
