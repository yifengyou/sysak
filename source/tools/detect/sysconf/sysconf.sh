#!/bin/sh
#****************************************************************#
# ScriptName: sysconf.sh
# Author: zhao.hang@alibaba-inc.com
# Create Date: 2021-08-16 15:22
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-08-16 15:22
# Function:
#***************************************************************#

#need modify RESULT_DIR on present system 
RESULT_DIR="/var/log/sysak"
CURRENT_VERSION=`uname -r`"-"`date  "+%Y%m%d-%H%M%S"`
SUBNAME="sysconf"
DIFF_RESULT="diff_result"
PID_MAX=`cat /proc/sys/kernel/pid_max`
CURRENT_TIME=`date  "+%Y%m%d-%H%M%S"`

CURRINFO_DIR="$RESULT_DIR/$SUBNAME/sysconf-$CURRENT_VERSION"
OLDINFO_DIR="$RESULT_DIR/$SUBNAME/sysconf-$OLD_VERSION"
DIFF_PATH="$RESULT_DIR/$SUBNAME/$DIFF_RESULT"
DIFF_CURR="$DIFF_PATH/sysconf-$CURRENT_VERSION"
#DIFF_OLD="$DIFF_PATH/sysconf-$OLD_VERSION"

procname_arry=(async_load_calc cgroups dma fb mtrr misc partitions mount swaps)

warn() {
	echo "sysAK:$SUBNAME: $*" >&2
}
die() {
    warn "$*"
    exit 0
}

usage() {
    echo "usage: sys_conf <option> [<args>]"
	echo "sysak sys_conf: compare the differences between the old and new kernel version"
    echo "all config file in /var/log/sysak/sysconf"
	echo "options: -h             help information"
	echo "         -c <version>   check old version system config"
	echo "         -g             collect current verion system config"
	echo "         -d             diff specify config with present system config"
	echo "         -p             diff specify configs"
	echo "example: check old version config and output config different"
	echo "./sys_config -c 4.19.91-24.al7.x86_64 -d "
	echo "./sys_config -p 4.19.91-24.al7.x86_64 4.19.91-23.al7.x86_64"
}

check_oldconfig() {
    if [ ! -e $RESULT_DIR/$SUBNAME/sysconf-$OLD_VERSION.tar.gz ]; then
        die "not find $RESULT_DIR/$SUBNAME/sysconf-${OLD_VERSION}.tar.gz sysconf file"
    fi
}

echo_fmt() {
	echo "$CURRENT_VERSION        $OLD_VERSION" > $DIFF_PATH/$1
}

system_info() {
    if [ -e $CURRINFO_DIR/sysconf_baseinfo ]; then
        rm $CURRINFO_DIR/sysconf_baseinfo
    fi
    echo "######kernel baseinfo######" >> $CURRINFO_DIR/sysconf_baseinfo
    uname -a >> $CURRINFO_DIR/sysconf_baseinfo
    cat /proc/cmdline >> $CURRINFO_DIR/sysconf_baseinfo

    if [ $1 -eq 1 ]; then
        echo_fmt diff_sysconf_baseinfo
        diff $CURRINFO_DIR/sysconf_baseinfo $DIFF_OLD/sysconf_baseinfo -B >> $DIFF_PATH/diff_sysconf_baseinfo
    fi
}

mod_list() {
    if [ -e $CURRINFO_DIR/sysconf_mod ]; then
        rm $CURRINFO_DIR/sysconf_mod
    fi
    echo "######mod list######" >> $CURRINFO_DIR/sysconf_mod
    lsmod |awk '{print $1}'| sort >> $CURRINFO_DIR/sysconf_mod

    if [ $1 -eq 1 ]; then
        echo_fmt diff_sysconf_mod
        diff $CURRINFO_DIR/sysconf_mod $DIFF_OLD/sysconf_mod -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_mod
    fi
}

compile_config_list() {
    if [ -e $CURRINFO_DIR/sysconf_compile_config ]; then
        rm $CURRINFO_DIR/sysconf_compile_config
    fi
    echo "######kernel config######" >> $CURRINFO_DIR/sysconf_compile_config
    zcat /proc/config.gz |grep "=y" | sort >> $CURRINFO_DIR/sysconf_compile_config

    if [ $1 -eq 1 ];then
        echo_fmt diff_sysconf_compile_config
        diff $CURRINFO_DIR/sysconf_compile_config $DIFF_OLD/sysconf_compile_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_compile_config
    fi
}

proc_paraments() {
    if [ -e $CURRINFO_DIR/sysconf_proc_config ]; then
        rm $CURRINFO_DIR/sysconf_proc_config
    fi
    echo "######proc config######" >> $CURRINFO_DIR/sysconf_proc_config

    let arry_len=${#procname_arry[@]}-1
    for i in `seq 0 $arry_len`;
    do
        if [ -e /proc/${procname_arry[$i]} ]; then
            echo -e "\n/proc/${procname_arry[$i]}" >> $CURRINFO_DIR/sysconf_proc_config 2>/dev/null;
            cat /proc/${procname_arry[$i]} >> $CURRINFO_DIR/sysconf_proc_config 2>/dev/null;
        fi
    done

    if [ $1 -eq 1 ]; then
        echo_fmt diff_sysconf_proc_config
        diff $CURRINFO_DIR/sysconf_proc_config $DIFF_OLD/sysconf_proc_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_proc_config
    fi
}

sysctl_paraments() {
    if [ -e $CURRINFO_DIR/sysconf_sysctl$2_config ]; then
        rm $CURRINFO_DIR/sysconf_sysctl$2_config
    fi
    echo -e "######sysctl $2 config######" >> $CURRINFO_DIR/sysconf_sysctl$2_config

    ##echo -e "\n/proc/sys/$2/$file" >> $CURRINFO_DIR/diff_sysconf_sysctl$2_config 2>/dev/null;
    sysctl -a | grep "$2"  >> $CURRINFO_DIR/sysconf_sysctl$2_config 2>/dev/null;

    if [ $1 -eq 1 ]; then
        echo_fmt diff_sysconf_sysctl$2_config
        diff $CURRINFO_DIR/sysconf_sysctl$2_config $DIFF_OLD/sysconf_sysctl$2_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_sysctl_$2
    fi
}

sysctl_all() {
    if [ -e $CURRINFO_DIR/sysconf_sysctl_config ]; then
        rm $CURRINFO_DIR/sysconf_sysctl_config
    fi
    echo -e "######sysctl config######" >> $CURRINFO_DIR/sysconf_sysctl_config
    sysctl -a >> $CURRINFO_DIR/sysconf_sysctl_config
    if [ $1 -eq 1 ]; then
        echo_fmt diff_sysconf_sysctl_config
        diff $CURRINFO_DIR/sysconf_sysctl_config $DIFF_OLD/sysconf_sysctl_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_sysctl
    fi

}

hardware_info(){
    if [ -e $CURRINFO_DIR/sysconf_hardware_info ]; then
        rm $CURRINFO_DIR/sysconf_hardware_info
    fi
    echo -e "######cpu info######" >> $CURRINFO_DIR/sysconf_hardware_info
    lscpu  >> $CURRINFO_DIR/sysconf_hardware_info

    if [ $1 -eq 1 ]; then
        echo_fmt diff_sysconf_hardware_info
        diff $CURRINFO_DIR/sysconf_hardware_info $DIFF_OLD/sysconf_hardware_info -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_hardware_info
    fi
}

diff_config() {
    if [ ! -d $RESULT_DIR/$SUBNAME ]; then
        die "$RESULT_DIR/$SUBNAME is not exist"
    fi
    if [ $1 -eq 1 ]; then
        check_oldconfig
        if [ -d $RESULT_DIR/$SUBNAME/$DIFF_RESULT ]; then
            rm -rf $RESULT_DIR/$SUBNAME/$DIFF_RESULT
        fi
        mkdir -p $DIFF_PATH
        tar -zxf $RESULT_DIR/$SUBNAME/sysconf-$OLD_VERSION.tar.gz -C $DIFF_PATH/
    fi

    mkdir -p $CURRINFO_DIR
    system_info $1
    mod_list $1
    compile_config_list $1
    proc_paraments $1

    sysctl_all $1
    hardware_info $1

    for mod in vm kernel fs user net dev debug abi;
    do
        sysctl_paraments $1 $mod
    done

    cd $RESULT_DIR/$SUBNAME/
    tar -zcf $RESULT_DIR/$SUBNAME/sysconf-$CURRENT_VERSION.tar.gz sysconf-$CURRENT_VERSION/
    cd -
    if [ $1 -eq 1 ]; then
        cp $RESULT_DIR/$SUBNAME/sysconf-$CURRENT_VERSION.tar.gz $DIFF_PATH/
    fi
}

collect_curr_config() {
    if [  ! -d $RESULT_DIR ]; then
        die "$RESULT_DIR is not exist"
    fi
    mkdir -p $RESULT_DIR/$SUBNAME
    diff_config 0
    rm -rf $CURRINFO_DIR
}

diff_check () {
    diff_config 1 diff
    rm -rf $CURRINFO_DIR
    rm -rf $OLDINFO_DIR
}
diff_all_config() {
    if [ ! -d $DIFF_PATH ]; then
        mkdir -p $DIFF_PATH
    fi
    
    tar -zxf $RESULT_DIR/$SUBNAME/$1.tar.gz -C $DIFF_PATH/
    tar -zxf $RESULT_DIR/$SUBNAME/$2.tar.gz -C $DIFF_PATH/
    echo "$1       $2" > $DIFF_PATH/diff_sysconf_baseinfo
    echo "$1       $2" > $DIFF_PATH/diff_sysconf_mod
    echo "$1       $2" > $DIFF_PATH/diff_sysconf_compile_config
    echo "$1       $2" > $DIFF_PATH/diff_sysconf_proc_config
    echo "$1       $2" > $DIFF_PATH/diff_sysconf_sysctl
    echo "$1       $2" > $DIFF_PATH/diff_sysconf_hardware_info
    diff $DIFF_PATH/$1/sysconf_baseinfo $DIFF_PATH/$2/sysconf_baseinfo -B >> $DIFF_PATH/diff_sysconf_baseinfo
    diff $DIFF_PATH/$1/sysconf_mod $DIFF_PATH/$2/sysconf_mod -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_mod
    diff $DIFF_PATH/$1/sysconf_compile_config $DIFF_PATH/$2/sysconf_compile_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_compile_config
    diff $DIFF_PATH/$1/sysconf_proc_config $DIFF_PATH/$2/sysconf_proc_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_proc_config
    diff $DIFF_PATH/$1/sysconf_sysctl_config $DIFF_PATH/$2/sysconf_sysctl_config -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_sysctl
    diff $DIFF_PATH/$1/sysconf_hardware_info $DIFF_PATH/$2/sysconf_hardware_info -y -W 200 --suppress-common-line -B >> $DIFF_PATH/diff_sysconf_hardware_info
}

set -- $(getopt -q hc:gp:d "$@")

while [ -n "$1" ]
do
    case "$1" in
    -h) usage
        exit 0
        ;;
    -c) [[ -z $2 ]] && usage
        OLD_VERSION=$2
        echo "$OLD_VERSION"
        let LEN=${#OLD_VERSION}-2
        OLD_VERSION=${OLD_VERSION:1:$LEN}
        DIFF_OLD="$DIFF_PATH/sysconf-$OLD_VERSION"
        check_oldconfig
        shift
        ;;
    -g) collect_curr_config
        exit 0
        ;;
    -d) diff_check 1
        exit 0
        ;;
    -p) [[ -z $2 ]] && die usage
        [[ -z $3 ]] && die usgae
        OLD_VERSION_1=$2
        OLD_VERSION_2=$2
        echo "$OLD_VERSION"
        let LEN_1=${#OLD_VERSION_1}-2
        let LEN_2=${#OLD_VERSION_2}-2
        OLD_VERSION_1=${OLD_VERSION_1:1:$LEN_1}
        OLD_VERSION_2=${OLD_VERSION_2:1:$LEN_2}
        DIFF_OLD="$DIFF_PATH/sysconf-diff"
        diff_all_config $OLD_VERSION_1 $OLD_VERSION_2
        exit 0
        ;;
    *)  [[ ! -z $1 ]] && shift && continue
        echo "is not option"
        usage
        exit 1
        ;;
    esac
done
