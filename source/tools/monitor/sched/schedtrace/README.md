1 function
抓取指定线程的所有现场信息，包括目标线程的唤醒、切换、系统调用、睡眠堆栈、信号以及目标线程上下文的中断、软中断。
2 usage
sysak schedtrace -p <pid> | -e <l|m|h> | -r <outfile> | -j <logfile> | -d <l|m|h> | -l
3 参数说明：
	-p 指定要trace的线程的线程id
	-s 指定trace日志的输出文件大小，单位MB，默认为512MB
	-e enable指定线程的trace开关，必须与-p 参数一起使用；-e还带一个参数，l表示low level信息量较少； m表示midlle level信息量比low level多 ；h表示high level，表示最多的调度信息
	-r 读取目标线程的trace日志到参数outfile
	-j 将-r读取到outfile裸数据转换成json格式的文件outfile.json
	-a 分析trace.log日志文件中某个任务被抢占或者不调度超过9ms的情况,需要与-p pid一起使用
	-d 关闭某个level的信息
	-l  查看当前schedtrace的配置情况
4示例
 抓取一个线程的tracelog
	1)使用high level级别打开指定线程schedtrace
	sysak schedtrace -p 1153 -e h
	2) 读取上面的tracelog
	sysak schedtrace -r 1153.trace.log  #读取完毕后会自动关闭前面的trace动作
	3) 将trace日志裸数据转换为json格式
	sysak schedtrace -j  1153.trace.log
	4) 分析一个trace日志中任务1153长时间不调度的情况
	sysak schedtrace -a trace.log -p 1153
