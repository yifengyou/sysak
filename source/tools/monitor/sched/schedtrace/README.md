sysak schedtrace <pid> | -e {l|m|h } |  [-s  [size]] |  -d [trace_out.log] |  -p [trace_out.log]  | [-S ]  | -l
参数说明:
	pid：位置参数，必须带有。表示需要抓取任务的线程id
	-s  指定trace日志的输出文件大小，单位MB，默认为512MB
	-e enable指定线程的trace开关；-e 可带level参数，l表示low level信息量较少； m表示midlle level信息量比low level多 ；h表示high level，表示最多的调度信息
	-j 将-r读取到outfile裸数据转换成json格式的文件outfile.json
	-p 对抓取的日志进行分析。 后面带可选参数为需要分析的日志文件，如果不带，默认分析当前路径下的schedtrace_out.log
	-d 关闭某个level的信息。后面带可选参数为需要将trace日志记录到哪个文件，如果不带，默认记录到当前路径下的schedtrace_out.log
	-S 是否记录堆栈信息
	-l  查看当前schedtrace的配置情况
示例: 抓取一个线程的tracelog
	1 使用high level级别打开指定线程schedtrace
		sysak schedtrace 88947 -e h
	2 读取上面的tracelog
		sysak schedtrace 88947 -d 88947.trace.log  #读取完毕后会自动关闭前面的trace动作
	3 分析trace log
		sysak schedtrace 88947  -p  88947.trace.log   
		#输出结果如下，检测到任务88947这个任务有在102ms的情况
		88947 was preempted 0.102060 sec
		<...>-49134 [016] d... 2516969.981458: sched_switch: prev_comm=tail prev_pid=49134 prev_prio=120 prev_state=x ==> next_comm=reactor_16 next_pid=88947 next_prio=120
