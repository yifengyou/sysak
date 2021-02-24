# 1、目录说明

mon_ko：内核监控ko

json_dump：导出监控数据为 json 格式的用户态工具

sh：批量命令执行脚本

# 2、使用步骤

## 2.1、编译准备

分别到 mon_ko， 和 json_dump 目录下执行make，编译出对应的ko和json_dump文件。将编译出来的ko、可执行程序和sh放同一目录，复制到需要监控的机器上去。

## 2.2、启动监控

执行./run.sh [pid]，开始监控关中断、长时间不调度、runqueue阻塞过长信息；如果不需要监控进程runq，也可以不带 pid参数

## 2.3、获取报告

执行 report.sh [file]，将捕捉到的信息以json格式输出，并追加到file文件中去。如果不带参数，则输出到stdout

## 2.4、 停止监控

执行 stop.sh 停止所有监控