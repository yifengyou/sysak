#!/bin/sh
#****************************************************************#
# ScriptName: iosdiag.sh
# Author: guangshui.lgs@alibaba-inc.com
# Create Date: 2021-07-02 11:44
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-07-02 11:45
# Function: 
#***************************************************************#
if [ "$SYSAK_WORK_PATH" != "" ]; then
WORK_PATH=$SYSAK_WORK_PATH
else
WORK_PATH=/usr/local/sbin/.sysak_compoents
fi
TOOLS_PATH=$WORK_PATH/tools/`uname -r`
LIB_PATH=$WORK_PATH/lib/`uname -r`
latency_bin=$WORK_PATH/tools/latency
data_analysis=$WORK_PATH/tools/iosdiag_data_analysis
iosdiag_dir="/var/log/sysak/iosdiag"
logfile="$iosdiag_dir/$1/result.log.seq"
logfile_arg="-f $logfile"

function usage() {
	echo "Usage: sysak iosdiag [options] subcmd [cmdargs]]"
	echo "       subcmd:"
	echo "              latency, io latency diagnosis"
	echo "       cmdargs:"
	echo "              -h, help info"
	echo "       options:"
	echo "              -u url, transfer datafile to remote url"
	echo "              -s latency|[..], stop diagnosis"
	#echo "              -f logfile, output log file"
}

function list() {
	ls $TOOLS_PATH
}

upload_data() {
	datapath=$iosdiag_dir/$1
	cd $datapath
	tar -zcf iosdiag_$1.tar.gz ./*
	curl -i -q  -X PUT -T iosdiag_$1.tar.gz $url
	rm -f iosdiag_$1.tar.gz
}

datafile_analysis() {
	python $data_analysis --$1 --stat --file $logfile $threshold_arg
}

enable_latency() {
	if [ ! -e "$latency_bin" ]; then
		echo "$latency_bin not found"
		echo "iosdiag latency not support '$(uname -r)', please report to the developer"
		exit -1
	fi
	threshold=$(echo "$*"|awk -F "-t" '{print $2}'|awk '{print $1}')
	[ "$threshold" != "" ] && { threshold_arg="-t $threshold"; }
	{
		flock -n 3
		[ $? -eq 1 ] && { echo "another latency is running."; exit -1; }
		trap disable_latency SIGINT SIGTERM SIGQUIT
		#mkdir -p `dirname $datafile`
		chmod +x $latency_bin
		rm $logfile_arg
		$SYSAK_WORK_PATH/../sysak btf
		$latency_bin $logfile_arg $* &
		wait $!
		disable_latency
	} 3<> /tmp/latency.lock
}

disable_latency() {
	pid=`ps -ef | grep "\$latency_bin" | awk '{print $2}'`
	if [ "$pid" != "" ]
	then
		kill -9 $pid 2>/dev/null
	fi

	datafile_analysis latency
	if [ -n "$url" ]; then
		upload_data latency
	fi
	exit 0
}


#execute command,every command need such args:
# -h/--help: command usage
# -f/--file: output files, default stdout
#            output format jason
# -d/--disable
function execute() {
	#echo cmd:$1 ${*:2}
	enable_$1 ${*:2}
}

while getopts 'hs:u:' OPT; do
	case $OPT in
		"u")
			url=$OPTARG
			;;
		"s")
			diag_stop=true
			subcmd=$OPTARG
			;;
		*)
			usage
			exit 0
			;;
	esac
done

if [ $diag_stop ]; then
	echo "disable $subcmd"
	disable_$subcmd
	exit 0
fi

subcmd=${@:$OPTIND:1}
subargs=${*:$OPTIND+1};
[ "$subcmd" != "latency" ] && { echo "not support subcmd $subcmd!!!"; usage; exit -1; }
execute $subcmd $subargs

