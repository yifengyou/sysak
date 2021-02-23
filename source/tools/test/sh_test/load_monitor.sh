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
	load=`cat /proc/loadavg | awk '{print $1}' | awk -F. '{print $1}'`
	if [ $load -gt 250 ]; then
		for pid in $(ls /proc/);
		do
			if [ "$pid" -gt 0 ] 2>/dev/null; then
				for tid in $(ls /proc/$pid/task/); do
					if [ "$tid" -gt 0 ] 2>/dev/null; then
						run=`cat /proc/$tid/status | grep "disk sleep" | wc -l`;
						if  [ "$run" -gt 0 ] 2>/dev/null; then
							echo $tid >> load_res.txt;
							cat /proc/$tid/status | grep Name >> load_res.txt;
							cat /proc/$tid/stack >> load_res.txt;
						fi;
					fi;
				done;
			fi;
		done
		exit
	fi
	
	sleep 5
done
