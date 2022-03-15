# iofsstat
iofsstat实现从进程和文件级别统计IO信息，传统的IO统计工具在如下场景下会略有不足：
1.在磁盘io被打满的情况下，希望观察是哪个进程贡献了比较多的IO，传统的工具只能从整个磁盘角度去统计io信息，如统计整盘的iops、bps，但不能统计单个进程所贡献的iops、bps
2.系统上统计到某个进程贡献了大量的IO，希望观察到这些IO最终是被哪个磁盘给消费，或者这些IO是在访问哪个文件，如果这个进程是来自某个容器，希望依然可以获取访问的文件以及此进程所在的容器

# sysak打包
在编译sysak的之前，需要在执行configure配置的时候加上--enable-target-iofsstat才能打包进sysak

# 使用
## 参数说明
```
usage: iofsstat.py [-h] [-d DEVICE] [-p PID] [-f]
interval

Report fs/block IO statistic for disk.

positional arguments:
    interval             Specify refresh interval(secs).

optional arguments:
    -h, --help           show this help message and exit
    -d DEVICE, --device DEVICE
                         Specify the disk name.
    -p PID, --pid PID    Specify the process id.
    -f, --fs             Report filesystem io statistic for partitions.

e.g.
    ./iofsstat.py -d vda 1
                         Report block-layer IO statistic for vda per 1secs
    ./iofsstat.py -d vda1 --fs 1
                         Report fs-layer IO statistic for vda1 per 1secs
```
## block-layer io统计
```
./iofsstat.py -d vdb 1 #间隔1秒统计一次vdb磁盘上的io

2022/01/19 12:04:38
comm                    pid     iops_rd     bps_rd          iops_wr     bps_wr
[dd]                    98675   1           4.0KB/s         259         32.4MB/s
[kworker/u12:0]         91022   1           4.0KB/s         198         167.5MB/s
[jbd2/vdb1-8]           19510   0           0               1           4.0KB/s
...
```
显示结果按照iops_rd与iops_wr的和作降序排列，如输出结果较多想只看某进程情况下，可以使用-p PID只查看指定进程，其中关键字段含义如下：
iops_rd: 进程贡献的读iops
bps_rd : 进程贡献的读bps
iops_wr: 进程贡献的写iops
bps_wr : 进程贡献的写bps

## fs-layer io统计
```
./iofsstat.py -d vdb1 --fs 1 #间隔1秒统计一次vdb磁盘上的io

2022/01/19 14:13:48
comm                pid     cnt_rd  bw_rd       cnt_wr  bw_wr       inode       filepath
dd                  55937   0       0           1096    137.0MB/s   9226        /home/data/tfatsf
...
```
显示结果按照bw_rd与bw_wr的和作降序排列，如输出结果较多想只看某进程情况下，可以使用-p PID只查看指定进程，其中关键字段含义如下：
cnt_rd: 读文件次数
bw_rd : 读文件"带宽"
cnt_wr: 写文件次数
bw_wr : 写文件"带宽"
inode : 文件inode编号
filepath: 文件路径, 当在一次采集周期内由于进程访问文件很快结束情况下，获取不到文件名则为"-"
如进程来自某个容器，在文件名后缀会显示[containterId:xxxxxx]

