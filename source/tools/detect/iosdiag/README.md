# iosdiag
iosdiag (IO storage diagnostics tools), IO存储诊断工具，目前包括已实现的IO延迟诊断功能以及正在实现的IO夯诊断或其他功能等等

# 代码目录结构
entry         ------- IO诊断功能入口代码
latency       ------- IO延迟诊断代码
data_analysis ------- IO诊断数据分析与结果输出代码

# 运行IO延迟诊断功能前置条件
由于基于eBPF实现，因此需要内核支持并启动eBPF

# 编译
在编译sysak的之前，需要在执行configure配置的时候加上--enable-libbpf --enable-target-iosdiag才能编译进sysak

# 使用
## 参数说明
###sysak iosdiag -h
Usage: sysak iosdiag [options] subcmd [cmdargs]]
       subcmd:
		latency, 执行io延迟诊断功能
       cmdargs:
		-h, 跟在子命令之后显示功能支持参数
       options:
		-u url, 指定url，将会通过curl命令把诊断日志文件打包上传到此url，不指定不上传
		-s latency, 停止诊断

###sysak iosdiag latency -h
Usage:  latency [OPTION] disk_devname

options:
	-t threshold, 指定超时IO的时间阈值(单位ms)，IO时延诊断将过滤完成耗时超过此阈值的IO(默认1000ms)
	-T time, 指定诊断运行时长(单位秒)后自动退出(默认10秒)

e.g.
	latency vda			诊断访问磁盘vda上耗时1000ms的IO，诊断10s后自动退出
	latency -t 10 vda		诊断访问磁盘vda上耗时10ms的IO，诊断10s后自动退出
	latency -t 10 -T 30 vda		诊断访问磁盘vda上耗时10ms的IO，诊断30s后自动退出

## 输出说明
### 控制台输出
#### 运行命令：
sysak iosdiag latency -t 1 -T 20 vda
#### 运行过程日志：
start iosdiag_virtblk load bpf
load iosdiag_virtblk bpf success
running...done
#### 运行结果输出：两个维度，整体IO的延迟分布情况(以百分比展示整体IO的延迟点)+输出延迟最大的前TOPn个IO的最大延迟点以及总延迟
15 IOs of disk vda over 1 ms, delay distribution:
os(block)    delay: 17.147%
os(driver)   delay: 0.009%
disk         delay: 82.84%
os(complete) delay: 0.002%
The first 10 IOs with the largest delay, more details:
seq   comm                pid       iotype  datalen         abnormal(delay:totaldelay)
11    kworker/u12:2       11943     W       4096            disk delay (145.56:256.88 ms)
12    kworker/u12:2       11943     W       4096            disk delay (145.46:256.66 ms)
15    kworker/u12:2       11943     W       4096            disk delay (217.39:217.51 ms)
14    jbd2/vda1-8         354       FWFS    4096            os(block) delay (143.42:152.93 ms)
13    kworker/u12:2       11943     W       4096            disk delay (145.05:145.30 ms)
3     kworker/u12:2       11943     W       4096            disk delay (113.80:114.00 ms)
5     kworker/u12:2       11943     W       8192            disk delay (112.97:113.14 ms)
1     kworker/u12:2       11943     W       4096            disk delay (111.79:111.96 ms)
10    kworker/u12:2       11943     W       8192            disk delay (111.62:111.78 ms)
4     kworker/u12:2       11943     W       4096            disk delay (111.11:111.30 ms)
more details see /var/log/sysak/iosdiag/latency/result.log*

### 日志文件说明
日志文件中的数据均以磁盘为单位以json数组的方式呈现
#### /var/log/sysak/iosdiag/latency/result.log
该日志文件描述的是每一个延迟IO的事件信息,通过seq可以从result.log.seq文件中索引到IO的延迟信息
{
    "summary":[			//以磁盘为一个单位的数组
        {
	    "diskname":"vda",	//磁盘盘符
	    "slow ios":[	//每一个该磁盘下的io为一个单位的数组
		{
		    "seq":"11",					//通过这个序号可以从result.log.seq中找到此IO的延迟分布
		    "time":"Thu Dec 23 14:42:10 2021",		//检测到次超时IO的时间
		    "abnormal":"disk delay (145.56:256.88 ms)",	//此IO的延迟最大的点(延迟最大的组件的延迟:总延迟)
		    "iotype":"W",				//此IO类型
		    "sector":23695488,				//此IO访问磁盘的具体偏移位置
		    "datalen":4096,				//次IO访问磁盘的数据量
		    "comm":"kworker/u12:2",			//发起此IO的进程
		    "pid":11943,				//进程ID
		    "cpu":"2 -> 4 -> 4"				//发起此IO的CPU -> 响应IO完成之后磁盘中断的CPU -> 磁盘IO完成后执行软中断的CPU
								//如只显示一个CPU编号，说明发起IO和执行中断的CPU相同,要注意也有磁盘是没有软中断流程的
		},
		{第二个IO事件信息},
		...
	    ]
	},
	{第二个磁盘},
	...
    ]
}
#### /var/log/sysak/iosdiag/latency/result.log.seq
该日志文件描述的是每一个延迟IO在各组建的延迟分布,通过seq可以从result.log文件中索引到IO的详细信息
{
    "summary":[			//以磁盘为一个单位的数组
        {
	    "diskname":"vda",	//磁盘盘符
	    "slow ios":[	//每一个该磁盘下的io延迟信息为一个单位的数组
		{
		    "seq":"11",				//通过这个序号可以从result.log中找到此IO的详细信息
		    "totaldelay":256884,		//此IO总耗时
		    "delays":[	//以此IO的每个组件的延迟情况为单位的数组，目前涉及的组建为：block、driver、disk、complete
			{
			    "component":"block",	//组建名
			    "delay":111300		//此IO在该组建的时延，单位us
			},
			{
			    "component":"driver",
			    "delay":25
			},
			{
			    "component":"disk",
			    "delay":145557
			},
			{
			    "component":"complete",
			    "delay":2
			}
		    ]
		},
		{第二个IO延迟信息},
		...
	    ]
	},
	{第二个磁盘},
	...
    ]
}
#### /var/log/sysak/iosdiag/latency/result.log.stat
该日志文件描述的是在磁盘角度，所有IO的延迟分布统计信息
{
    "summary":[			//以磁盘为一个单位的数组
        {
	    "diskname":"vda",	//磁盘盘符
	    "delays":[		//以每个组件的延迟情况为单位的数组，目前涉及的组建为：block、driver、disk、complete
		{
		    "component":"os(block)",	//组建名
		    "percent":"17.147%",	//在捕获的该磁盘的IO中，经统计在此组件耗时的百分比
		    "max":143422,		//在此组件的最大耗时，单位us
		    "min":76,			//在此组件的最小耗时，单位us
		    "avg":24518			//在此组件的平均耗时，单位us
		},
		{"os(driver)" 延迟情况},
		{"disk" 延迟情况},
		{ "os(complete)" 延迟情况}
	    ]
	},
	{第二个磁盘},
	...
    ]
}


