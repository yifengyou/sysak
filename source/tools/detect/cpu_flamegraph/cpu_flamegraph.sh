#!/bin/sh
#****************************************************************#
# ScriptName: cpu_flamegraph.sh
# Author: haomai.qyx@alibaba-inc.com
# Create Date: 2021-06-02 15:48
# Function:
#***************************************************************#
############# Global Variable ############
CURDATE=$(date "+%Y-%m-%d-%H-%M-%S")
SLOGDIR="/var/log/sysak"
WORKDIR="$(hostname)_sysak_cpu_fg"
LOGDIR="${SLOGDIR}/${WORKDIR}"
LOGFILE="${LOGDIR}/sysak_cpu_flamegraph.log"
CURPATH="$SYSAK_WORK_PATH/tools"
LOCK_FILE="/var/log/$(hostname).cpufg_pid"

perf_data="${LOGDIR}/perf.${CURDATE}.data"
script_out="${LOGDIR}/perf-${CURDATE}.out"
folded_out="${LOGDIR}/out-${CURDATE}.folded"
perf_svg="${LOGDIR}/perf.${CURDATE}.svg"

duration=20
cpu_arg="-a"

pid="0"

clean="False"
aso_output="False"
success=0
fail=1

################################## Utility Function ################################
## help message
usage() {
	echo "$(basename $0): collect cpu perf flamegraph"
	echo "options: -h, help information"
	echo "         -d, duration, perf record time, default to 20 seconds"
	echo "         -C, Collect samples only on the list of CPUs provided. Multiple CPUs can be provided as a comma-separated list with
           no space: 0,1. Ranges of CPUs are specified with -: 0-2."
	echo "         -p, specifed pid"
	echo "         -A, print with ASO format"
	echo "         -c, clean svg files, only clean svg files not collect cpu flamegraph"
}
## info write in $LOGFILE
info() {
    local info="$1"
    local cmd="echo -e $info"
	local ts="[`date "+%Y%m%d%H%M%S"`]"
    echo $ts    >> $LOGFILE
    eval $cmd   >> $LOGFILE 2>&1
    echo ""     >> $LOGFILE
}
## message write to stdout and consume by host-service
msg() {
    local strings="$1"
	if [ "x${aso_output}" = "xTrue" ];
	then
		echo "{\"msg\":\"${strings}\"}"
	else
		echo "$strings"
	fi
}
## error message in stdout and exit
error() {
	local strings="$1"
	if [ "x${aso_output}" = "xTrue" ];
	then
		echo "{\"type\":\"${type}\",\"status\": false,\"result\":\"${strings}\"}"
	else
		echo "$strings"
	fi
    exit 1
}
## cpu_flamegraph message when completed successfully
cpu_fg_msg() {
    local type="$1"
	local strings="$2"
	if [ "x${aso_output}" = "xTrue" ];
	then
		if [ "${type}" = "cpu_flamegraph" ];
		then
			echo "{\"type\":\"${type}\",\"status\": true,\"result\":\"火焰图生成完成\",\"details\": [{\"name\":\"下载地址\",\"value\":\"$strings\",\"downloadFile\":true}]}"
		else
			echo "{\"type\":\"${type}\",\"status\": true,\"result\":\"火焰图清理完成\"}"
		fi
	else
		echo "$strings"
	fi
}
## check command exist or not
if_command_exist() {
    local cmd=$1
    command -v $cmd > /dev/null
    return $?
}
## run command and redirect stdout and stderr to log
cmd_log()
{
	local log=$1
	shift
    local cmd=$@
    local res=$fail

    echo "Calling: ${cmd:0:60}" >> $log

    echo "Command: $cmd" >> $log
    eval $cmd >> $log 2>&1
    res=$?
    return $res
}
## run perf record to generate perf.data
run_perf_record() {
	local cmd="perf record -F 49 ${cpu_arg} -g -o ${perf_data} sleep ${duration}"
	if [ "x${pid}" != "x0" ];
	then
		cmd="perf record -g -o ${perf_data} -p ${pid} sleep ${duration}"
	fi
	cmd_log "$LOGFILE" "$cmd"
}
## generate flamegraph
convert_svg() {
	## perf script to dump the stack samples
	perf script -i ${perf_data} >${script_out} 2>>$LOGFILE
	[ $? -eq $fail ] && info "perf script failed" && return $fail
	[ ! -e ${script_out} ] && info "${script_out} does not exsit ..." && return $fail
	## stackcollapse-perf.pl to folded stack samples into single lines per-stack
	${CURPATH}/stackcollapse-perf.pl ${script_out} > ${folded_out}
	[ $? -eq $fail ] && info "stackcollapse-perf.pl failed" && return $fail
	[ ! -e ${folded_out} ] && info "${folded_out} does not exsit ..." && return $fail
	## flamegraph.pl to converted folded stack traces into the SVG
	${CURPATH}/flamegraph.pl ${folded_out} > ${perf_svg}
	[ $? -eq $fail ] && info "flamegraph.pl failed" && return $fail
	[ ! -e ${perf_svg} ] && info "${perf_svg} does not exsit ..." && return $fail
	return $success
}
## collect flamegraph
collect_framegraph() {
	local PERF="perf"
	local CMD_TYPE="cpu_flamegraph"
	## check perf command exist or not
	if_command_exist ${PERF}
	[ $? -eq $fail ] && msg "${PERF} command not found" && return $fail
	## run perf record
	run_perf_record 
	[ $? -eq $fail ] && msg "perf record failed" && return $fail
	[ ! -e ${perf_data} ] && msg "${perf_data} does not exsit ..." && return $fail
	## generate flamegraph svg
	convert_svg
	[ $? -eq $fail ] && msg "convert svg failed" && return $fail
	cpu_fg_msg "${CMD_TYPE}" "${perf_svg}" && return $success
}
## clean tmp files function
clean_tmp() {
	local tmp_files=(
		"${LOGDIR}/perf*data"
		"${LOGDIR}/perf*out"
		"${LOGDIR}/out*folded"
		"${LOCK_FILE}"
	)
	for tmp_file in "${tmp_files[@]}";
	do
		ls ${tmp_file} &>/dev/null
		if [ $? -eq 0 ];
		then
			for file in `ls ${tmp_file}`;
			do
				[ -f $file ] && info "clean $file" && rm --preserve-root $file || info "rm $file failed "
			done
		fi
	done
	info "clean tmp is called"
}
## clean svg files function
clean_svg()
{
	local all_perf_svgs="${LOGDIR}/perf.*.svg"
	local CMD_TYPE="cpu_fgclean"
	info "Calling sysak cpu flamegraph clean svg ..."
	ls ${all_perf_svgs} &>/dev/null
	if [ $? -eq 0 ];
	then
		for svg in `ls ${all_perf_svgs}`;
		do
			[ -f $svg ] && info "clean $svg" && rm --preserve-root $svg || info "rm $svg failed "
		done
	fi
	# [ -e $LOCK_FILE ] && info "clean $LOCK_FILE" && rm $LOCK_FILE
    cpu_fg_msg "${CMD_TYPE}" "cleanup completed" && return $success
}
## prepare function to create log dir
prepare_to_run()
{
    export LANG=C
	if [ ! -d $LOGDIR ];
	then
		mkdir -p $LOGDIR || error "create $LOGDIR failed"
	fi
	return $success
}
## check instance exsit or not, only allow single instance running
check_single_instance()
{
    if [ -f ${LOCK_FILE} ];then
        error "Another $(basename $0) is running, please waiting it finish and then retry !"
    fi
    echo "$$" > "${LOCK_FILE}"
}
## parse subcommand
while getopts 'd:C:p:chA' OPT; do
	case $OPT in
		"h")
			usage
			exit 0
			;;
		"d")
			duration="$OPTARG"
			;;
		"C")
			cpu_arg="-C $OPTARG"
			;;
		"p")
			pid="$OPTARG"
			;;
		"A") 
			aso_output="True"
			;;
		"c")
			clean="True"
			;;
		*)
			usage
			exit 1
			;;
	esac
done

### main logic here
check_single_instance
trap clean_tmp EXIT

if [ "x$clean" = "xTrue" ];
then
	clean_svg
else
	prepare_to_run
	collect_framegraph
fi
