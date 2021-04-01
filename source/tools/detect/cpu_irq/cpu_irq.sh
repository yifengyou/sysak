#!/bin/sh
#****************************************************************#
# ScriptName: cpu_irq.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-09 15:21
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-09 15:21
# Function: 
#***************************************************************#
maxcpu=`lscpu | grep "On-line" | awk -F- '{print $3}'`
if [ "$1" -ge 0 ] 2>/dev/null; then
	if [ $1 -gt $maxcpu ]; then
		echo cpu is not valid
		exit
	fi
else
	echo Usage:
	echo "     sysak cpu_irq cpu"
	exit
fi

echo show cpu $1
OLD_IFS="$IFS"
for irq in `ls /proc/irq`; do
	if [ "$irq" -ge 0 ] 2>/dev/null; then
		cpulist=`cat /proc/irq/$irq/smp_affinity_list`;
		IFS="," 
		arr=($cpulist) 
		for item in ${arr[@]}; do
			IFS="-"
			range=($item)			
			min=${range[0]}
			max=${range[1]}
			if [ ${range[0]} -eq $1 ]; then
				echo $irq
			else
				if [[ ${range[0]} -lt $1 ]] && [[ ${range[1]} -ge $1 ]]; then
					echo $irq
				fi
			fi
		done
	fi
done
IFS="$OLD_IFS"
