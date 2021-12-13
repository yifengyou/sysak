#!/bin/sh
#****************************************************************#
# ScriptName: cpuirq.sh
# Author: $SHTERM_REAL_USER@alibaba-inc.com
# Create Date: 2021-02-09 15:21
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2021-02-09 15:21
# Function: 
#***************************************************************#

usage() {
	echo "sysak cpuirq: show irq information"
        echo "options: -h, help information"
        echo "         -c cpu, specify the cpu"
        echo "         -i interval, the interval checking the irq status"
        echo "         -b, show irq bind on cpu"
        echo "         -t, show top irq during the interval time"
}

irq_bind() {
if [ "$cpu" -lt 0 ] 2>/dev/null; then
	usage
	exit
fi

echo show irq bind on cpu $cpu
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
			if [ ${range[0]} -eq $cpu ]; then
				echo $irq
			else
				if [[ ${range[0]} -lt $cpu ]] && [[ ${range[1]} -ge $cpu ]]; then
					echo $irq
				fi
			fi
		done
	fi
done
IFS="$OLD_IFS"
}

datadir="/var/log/sysak"
interval=5
show_top="false"
show_bind="false"
cpu=-1

top_irq() {
echo > $datadir/cpuirq1.log
echo > $datadir/cpuirq2.log
cat /proc/interrupts | while read line; do echo $line |awk '{for(i=2;i<=NF-2;i++) sum+=$i} END{print $1sum":"$NF}' >> $datadir/cpuirq1.log;done
sleep $interval
cat /proc/interrupts | while read line; do echo $line |awk '{for(i=2;i<=NF-2;i++) sum+=$i} END{print $1sum":"$NF}' >> $datadir/cpuirq2.log;done
diff -y --suppress-common-line -B /var/log/sysak/cpuirq1.log /var/log/sysak/cpuirq2.log | awk -F ":" '{print $4-$2" "$1":"$5}' |  sort  -nr > $datadir/cpuirq.log

echo the top interrups at last $interval seconds:
cat $datadir/cpuirq.log | while read line; do
	irqcnt=`echo $line | awk '{print $1}'`
	if [ $irqcnt -lt 1000 ]; then
		exit;
	fi
	echo $line
done
}

top_irq_cpu() {
echo > $datadir/cpuirq1.log
echo > $datadir/cpuirq2.log
cat /proc/interrupts | while read line; do echo $line |awk -v cpu=$cpu '{print $1$(2+cpu)":"$NF}' >> $datadir/cpuirq1.log;done
sleep $interval
cat /proc/interrupts | while read line; do echo $line |awk -v cpu=$cpu '{print $1$(2+cpu)":"$NF}' >> $datadir/cpuirq2.log;done
diff -y --suppress-common-line -B /var/log/sysak/cpuirq1.log /var/log/sysak/cpuirq2.log | awk -F ":" '{print $4-$2" "$1":"$5}' |  sort  -nr > $datadir/cpuirq.log

echo the top interrups on cpu$cpu at last $interval seconds:
cat $datadir/cpuirq.log | while read line; do
	irqcnt=`echo $line | awk '{print $1}'`
	if [ $irqcnt -lt 1000 ]; then
		exit;
	fi
	echo $line
done
}

while getopts 'i:c:bth' OPT; do
        case $OPT in
                "h")
                        usage
                        exit 0
                        ;;
                "c")
			maxcpu=`lscpu | grep "On-line" | awk -F- '{print $3}'`
			echo maxcpu=$maxcpu
			if [ "$OPTARG" -ge 0 ] 2>/dev/null; then
				if [ "$OPTARG" -gt "$maxcpu" ]; then
					echo cpu is not valid
					exit -1
				fi
			else
				echo cpu is not valid
				exit -1
			fi
                        cpu=$OPTARG
                        ;;
                "i")
                        interval="$OPTARG"
                        ;;
                "t")
                        show_top="true"
                        ;;
                "b")
                        show_bind="true"
                        ;;
                *)
                        usage
                        exit -1
                ;;
        esac
done

if [ $show_top == "true" ];then
	if [ "$cpu" -ge 0 ] 2>/dev/null; then
		top_irq_cpu
	else
		top_irq
	fi
fi

if [ $show_bind == "true" ];then
	irq_bind
fi
