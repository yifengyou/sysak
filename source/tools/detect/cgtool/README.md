1. cgtool工具介绍
==================

cgtool(Cgroup Tool)是Cgroup子系统流程跟踪和问题诊断工具集。主要包括：
    memcg_usage: 统计memcg子系统memory.usage_in_bytes中详细进程使用信息；
    memcg_show: 监控各个memcg子系统中usage,rss,cache等数据；
    cpuacct_load：统计cpuacct子系统中cpu的aveload；
    cgcheck：系统cgroup健康检查工具；

2. 代码目录
==================
    cgrun: cgtool执行脚本
    cgtool*.h：公共库文件
    其它是以工具命名的目录

3. 编译
==================
./configure --enable-libbpf --enable-target-cgtool --enable-target-cgtool
make

4. 工具使用说明
==================

4.1 注意事项
无

4.2 cgtool工具
4.2.1 命令说明
sysak cgtool [options] [cgtool [cgtoolargs]]
  options: -h, help information
           -l, list all tools for cgroup
  cgtool:
           tool name for list
  cgtoolargs:
           args for the tool, -h get more

4.2.2 举例
#举例1：列出所支持的tools
#sysak cgtool -l
memcg_usage # Tracing memory usage of the memory cgroup
cpuacct_load # Tracing cpu load for the cpuacct cgroup

#举例2: 使用memcg_usage工具
见5.1

5. tools使用说明
==================

5.1 memcg_usage
5.1.1 命令说明
sysak cgtool memcg_usage [OPTION...]
  -b, --btf=BTF_PATH         Specify path of the custom btf
  -d, --debug                Enable libbpf debug output
  -f, --dir=dir              cgroup dir
  -t, --timeout=time         time out
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

5.1.2 举例
#举例1：统计memcg目录1秒总体进程内存使用情况
#sysak cgtool memcg_usage -t 1
task number:4 cgroup dir:/sys/fs/cgroup/memory/
 PID    TID       COMM       PGSIZE
-----------------------------------
29084  29084  systemd-cgroups  31
29080  29080  systemd-cgroups  31
29055  29055  systemd-cgroups  30
1      1      systemd          144

task number:2 cgroup dir:/sys/fs/cgroup/memory/yagent_script
 PID    TID       COMM       PGSIZE
-----------------------------------
29025  29025  sh               151
29089  29089  hostinfo         71

#举例2: 统计单一memcg组1秒进程内存使用情况
#sysak cgtool memcg_usage -t 1 -f /sys/fs/cgroup/memory/user.slice
task number:5 cgroup dir:/sys/fs/cgroup/memory/user.slice
 PID    TID       COMM       PGSIZE
-----------------------------------
31085  31085  grep             49
31087  31087  tail             28
31084  31084  ps               121
31083  31083  sh               85
31086  31086  awk              48

5.2 cpuacct_load
5.2.1 命令说明
sysak cgtool cpuacct_load [OPTION...]
  -b, --btf=BTF_PATH         Specify path of the custom btf
  -d, --debug                Enable libbpf debug output
  -f, --dir=dir              cgroup dir
  -t, --timeout=time         time out
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

5.2.2 举例
#举例1：统计cpuacct目录60秒负载
#sysak cgtool cpuacct_load -t 60
cgroup dir:/sys/fs/cgroup/cpuacct/h2o
times:
avenrun0: 126 115 105 96
avenrun1: 31 30 29 28
avenrun2: 8 7 6 5
load0: 0.06 0.06 0.05 0.05
load1: 0.02 0.01 0.01 0.01
load2: 0.00 0.00 0.00 0.00

cgroup dir:/sys/fs/cgroup/cpuacct/docker
times:
avenrun0: 0 0 0 0
avenrun1: 37 36 35 34
avenrun2: 24 23 22 21
load0: 0.00 0.00 0.00 0.00
load1: 0.02 0.02 0.02 0.02
load2: 0.01 0.01 0.01 0.01

cgroup dir:/sys/fs/cgroup/cpuacct/docker/26f45842eb4304617e0d121a384a7a0fcb7c25e0420771424102dde7f3886a28
times:
avenrun0: 0 0 0 0
avenrun1: 37 36 35 34
avenrun2: 24 23 22 21
load0: 0.00 0.00 0.00 0.00
load1: 0.02 0.02 0.02 0.02
load2: 0.01 0.01 0.01 0.01

#举例2: 统计单一cpuacct组60秒负载
#sysak cpuacct_load -t 60 -f /sys/fs/cgroup/cpuacct/h2o
cgroup dir:/sys/fs/cgroup/cpuacct/h2o
times:
avenrun0: 232 213 195 179 164 315
avenrun1: 60 59 58 57 56 90
avenrun2: 15 14 13 12 11 22
load0: 0.11 0.10 0.10 0.09 0.08 0.15
load1: 0.03 0.03 0.03 0.03 0.03 0.04
load2: 0.01 0.01 0.01 0.01 0.01 0.01

5.3 memcg_show
5.3.1 命令说明
  sysak cgtool memcg_show [OPTION...] 
    -h, help information
    -i, detection time interval, default: 10s
    -t, detection times, default: 5 times
    -u, [B/KB/MB/G], default: MB
    -d, memcg dir, default: /sys/fs/cgroup/memory
    
Examples:
  sysak cgtool memcg_show
  sysak cgtool memcg_show -i 60 -t 10 -u G

5.3.2 举例
#举例1：每隔1s监控/sys/fs/cgroup/memory/agent/目录memory数据，监控5次后结束
#sysak cgtool memcg_show -i 1 -t 5 -d /sys/fs/cgroup/memory/agent/
==============================================
/sys/fs/cgroup/memory/agent//Argus
usage: 0 0 0 0 0
rss: 40960 40960 40960 40960 40960
cache: 0 0 0 0 0
swap: 0 0 0 0 0
cache+rss+swap: 40960 40960 40960 40960 40960
kmemusage: 0 0 0 0 0
memswusage: 0 0 0 0 0

==============================================
/sys/fs/cgroup/memory/agent//staragent
usage: 69574656 69574656 70127616 69578752 69582848
rss: 13565952 13565952 14139392 13787136 13787136
cache: 55734272 55734272 55734272 55734272 55734272
swap: 0 0 0 0 0
cache+rss+swap: 69300224 69300224 69873664 69521408 69521408
kmemusage: 0 0 0 0 0
memswusage: 69574656 69574656 70127616 69578752 69582848

每一列数据为1次监控取值。

5.4 cgcheck
详见cgcheck/README.md
