1. cgcheck工具介绍
==================

cgcheck(Cgroup Check)是对系统cgroup配置、内存使用状态等健康状态检查工具。
主要包括：
1) 检查Cgroup子组是否过多(超过1000)，可能造成系统卡顿；

2. 代码目录
==================
    cgcheck.py: cgcheck执行脚本

3. 使用说明
==================
sysak cgtool cgcheck

#举例1：系统cgroup数量过多
#sysak cgtool cgcheck
cgroup子系统:memory 数量:1502 层级:4

