#!/bin/sh
#****************************************************************#
# ScriptName: sys_monitory.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-06 10:53
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-06 10:53
# Function: 
#***************************************************************#
while :;
do
	sys_util=`mpstat 1 1 | grep Average | awk '{print $5}' | awk -F. '{print $1}'`
	if [ $sys_util -gt 40 ]; then
		perf record -a -g sleep 10;
		exit
	fi
	
	sleep 5
done
