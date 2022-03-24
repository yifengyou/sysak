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
hangdetect_bin=$TOOLS_PATH/hangdetect
data_analysis=$WORK_PATH/tools/iosdiag_data_analysis
logfile="/var/log/sysak/iosdiag/$1/result.log.seq"
threshold_arg="-t 1000"

function usage() {
	echo "Usage: sysak iosdiag [options] subcmd [cmdargs]"
	echo "       subcmd:"
	echo "              latency, io latency diagnosis"
	echo "              hangdetect, io hang diagnosis"
	echo "       cmdargs:"
	echo "              -h, help info"
	echo "       options:"
	echo "              -u url, transfer datafile to remote url"
	echo "              -s latency|[hangdetect], stop diagnosis"
}

upload_data() {
	datapath=$(dirname $logfile)
	cd $datapath
	tar -zcf iosdiag_$1.tar.gz ./result.log*
	curl -i -q  -X PUT -T iosdiag_$1.tar.gz $url
	rm -f iosdiag_$1.tar.gz
}

datafile_analysis() {
	if [ -e "$logfile" ]
	then
		python $data_analysis --$1 -s -f $logfile $threshold_arg
	fi
}

hang_mod_depend()
{
	res=`lsmod | grep sysak`
	if [ -z "$res" ]; then
		insmod $LIB_PATH/sysak.ko
		if [ $? -ne 0 ]; then
			echo "insmod ko failed, please check the ko files."
			exit $?
		fi
	fi
}

enable_hangdetect() {
	if [ ! -e "$hangdetect_bin" ]; then
		echo "$hangdetect_bin not found"
		echo "iosdiag hangdetect not support '$(uname -r)', please report to the developer"
		exit -1
	fi
	{
		flock -n 3
		[ $? -eq 1 ] && { echo "another hangdetect is running."; exit -1; }
		trap disable_hangdetect SIGINT SIGTERM SIGQUIT
		#mkdir -p `dirname $datafile`
		hang_mod_depend
		chmod +x $hangdetect_bin
		rm -f $(dirname $logfile)/result.log*
		$hangdetect_bin $*
		wait $!
		disable_hangdetect
	} 3<> /tmp/hangdetect.lock
}

disable_hangdetect() {
	pid=`ps -ef | grep "\$hangdetect_bin" | awk '{print $2}'`
	if [ "$pid" != "" ]
	then
		kill -9 $pid 2>/dev/null
	fi

	res=`lsmod | grep sysak`
	if [ ! -z "$res" ]; then
		rmmod sysak
	fi

	datafile_analysis hangdetect
	if [ -n "$url" ]; then
		upload_data hangdetect
	fi
	exit 0
}

enable_latency() {
	if [ ! -e "$latency_bin" ]; then
		echo "$latency_bin not found"
		echo "iosdiag latency not support '$(uname -r)', please report to the developer"
		exit -1
	fi
	{
		flock -n 3
		[ $? -eq 1 ] && { echo "another latency is running."; exit -1; }
		trap disable_latency SIGINT SIGTERM SIGQUIT
		#mkdir -p `dirname $datafile`
		chmod +x $latency_bin
		rm -f $(dirname $logfile)/result.log*
		$SYSAK_WORK_PATH/../sysak btf
		$latency_bin $* &
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
	threshold=$(echo "$*"|awk -F "-t" '{print $2}'|awk '{print $1}')
	[ "$threshold" != "" ] && { threshold_arg="-t $threshold"; }
	logd=$(echo "$*"|awk -F "-f" '{print $2}'|awk '{print $1}')
	[ "$logd" != "" ] && { logfile=$logd/result.log.seq; }
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
[ "$subcmd" != "latency" -a "$subcmd" != "hangdetect" ] && { echo "not support subcmd $subcmd!!!"; usage; exit -1; }
execute $subcmd $subargs

