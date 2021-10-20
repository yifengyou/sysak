# -*- coding: utf-8 -*-

softlockup={
    "category":"MISC",
    "level":"critical",
    "name":"softlockup日志检查",
    "desc":"发生softlockup说明机器存在严重hang机风险",
    "solution":"",
    "summary_format":"发生softlockup %s次\n"
}

hungtask={
    "category":"MISC",
    "level":"error",
    "name":"hungtask日志检查",
    "desc":"发生hungtask说明应用存在hang风险",
    "solution":"",
    "summary_format":"发生hungtask %s次\n"
}

rcustall={
    "category":"CPU",
    "level":"critical",
    "name":"rcustall日志检查",
    "desc":"发生rcustall说明机器存在严重hang机风险",
    "solution":"",
    "summary_format":"发生rcustall %s次\n"
}

schedinatomic={
    "category":"CPU",
    "level":"error",
    "name":"schedinatomic日志检查",
    "desc":"发生schedinatomic可能会导致应用不再被调度执行",
    "solution":"",
    "summary_format":"发生schedinatomic %s次\n"
}

pageallocfail={
    "category":"MEM",
    "level":"warning",
    "name":"pageallocfail日志检查",
    "desc":"发生pageallocfail说明机器内存不足或者内存碎片化严重存在稳定性风险",
    "solution":"",
    "summary_format":"发生pageallocfail %s次\n"
}

oom={
    "category":"MEM",
    "level":"warning",
    "name":"oom日志检查",
    "desc":"发生oom说明机器内存不足或者cgroup内存配置异常",
    "solution":"",
    "summary_format":"发生oom %s次\n"
}

hotfixloaderr={
    "category":"HOTFIX",
    "level":"error",
    "name":"hotfixloaderr日志检查",
    "desc":"发生hotfixloaderr说明有hotfix装载失败导致解决稳定性问题的hotfix不生效影响系统稳定性",
    "solution":"",
    "summary_format":"发生hotfix装载失败报警 %s次\n"
}

listcorruption={
    "category":"MISC",
    "level":"critical",
    "name":"listcorruption日志检查",
    "desc":"发生listcorruption说明内存存在bug有宕机风险",
    "solution":"",
    "summary_format":"发生listcorruption %s次\n"
}

kernelwarn={
    "category":"MISC",
    "level":"warning",
    "name":"kernelwarn日志检查",
    "desc":"发生kernelwarn说明内核存在报警需要分析是否是正常报警，异常报警需要治理",
    "solution":"",
    "summary_format":"发生kernelwarn %s次\n"
}

ioerror={
    "category":"IO",
    "level":"critical",
    "name":"ioerror日志检查",
    "desc":"发生ioerror说明存储盘可能存在问题导致稳定性风险",
    "solution":"",
    "summary_format":"发生ioerror %s次\n"
}

fsreadonly={
    "category":"IO",
    "level":"error",
    "name":"fsreadonly日志检查",
    "desc":"发生fsreadonly说明存在文件系统异常导致文件系统只读",
    "solution":"",
    "summary_format":"发生fsreadonly %s次\n"
}

ext4error={
    "category":"IO",
    "level":"critical",
    "name":"ext4error日志检查",
    "desc":"发生ext4error说明文件系统错误需要重启机器fsck修复",
    "solution":"",
    "summary_format":"发生ext4error %s次\n"
}

nf_conntrack_table_full={
    "category":"NET",
    "level":"warning",
    "name":"nf_conntrack_table_full日志检查",
    "desc":"",
    "solution":"",
    "summary_format":"发生nf_conntrack_table_full %s次\n"
}

MCE={
    "category":"MCE",
    "level":"critical",
    "name":"机器MCE检查",
    "desc":"存在MCE错误说明硬件有问题存在较大稳定性风险,建议硬件检修",
    "solution":"",
    "summary_format":"该机器存在mce错误\n"
}

diskerr={
    "category":"DISK",
    "level":"critical",
    "name":"硬盘错误检查",
    "desc":"硬盘硬件错误说明存在较大稳定性风险,建议硬件检修",
    "solution":"",
    "summary_format":"该机器存在硬盘硬件错误,建议硬件检修\n"
}

PANIC={
    "category":"PANIC",
    "level":"critical",
    "name":"宕机检查",
    "desc":"检查机器是否发生宕机,如果发生则机器存在严重稳定性风险",
    "solution":"",
    "summary_format":"本地机器上检查到宕机%s次,宕机时间:%s\n"
}

highsys={
    "category":"CPU",
    "level":"warning",
    "name":"CPU利用率异常检查",
    "desc":"检查一天内CPU sys/io/softirq超过30%的时间点,如果存在容易引起业务RT抖动",
    "solution":"",
    "summary_format":"CPU利用率高异常:\n%s"
}

highload={
    "category":"CPU",
    "level":"warning",
    "name":"Load高检查",
    "desc":"检查一天内Load飙高的时间点,Load高会影响业务QPS和RT",
    "solution":"",
    "summary_format":"Load高异常:\n%s"
}

directreclaim={
    "category":"MEM",
    "level":"warning",
    "name":"Cgroup发生直接内存回收检查",
    "desc":"检查机器开机到现在是否存在Cgroup发生频繁直接内存回收,如果发生说明该Cgroup容易发生应用RT抖动",
    "solution":"",
    "summary_format":"cgroup存在频繁directreclaim达%s次\n"
}

unreclaimslab={
    "category":"MEM",
    "level":"warning",
    "name":"不可回收Slab内存大小检查",
    "desc":"不可回收Slab内存过高可能会导致系统异常",
    "solution":"",
    "summary_format":"存在过高不可回收Slab内存达%skB\n"
}

lowfree={
    "category":"MEM",
    "level":"warning",
    "name":"free内存检查",
    "desc":"free内存不足,容易引起sys飙高和频繁OOM,甚至ssh失联",
    "solution":"",
    "summary_format":"free内存不足,仅占总内存%s%%,容易引起sys飙高和频繁OOM,甚至ssh失联\n"
}

memleak={
    "category":"MEM",
    "level":"error",
    "name":"内存泄漏检查",
    "desc":"内存泄漏容易引起内存不足OOM导致系统不稳定",
    "solution":"",
    "summary_format":"诊断slab和内存泄漏: %s\n"
}

highdentry={
    "category":"MEM",
    "level":"warning",
    "name":"dentry数量检查",
    "desc":"dentry数量过大容易导致遍历dentry耗时长导致sys飙高风险",
    "solution":"",
    "summary_format":"dentry数量过大,当前数量:%s,存在遍历dentry耗时长导致sys飙高风险\n"
}

memfrag={
    "category":"MEM",
    "level":"warning",
    "name":"高阶内存检查",
    "desc":"高阶内存不足,存在内存碎片问题,可能会导致申请高阶内存失败,或者由于内存页频繁合并导致系统sys高,load高",
    "solution":"",
    "summary_format":"高阶内存不足,存在内存碎片问题,可能会导致申请高阶内存失败或者由于内存页频繁合并导致系统sys高,load高\n"
}

highiowait={
    "category":"IO",
    "level":"warning",
    "name":"iowait高检查",
    "desc":"检查一天内iowait高时间点,高iowait容易导致说明IO压力大或者存储盘故障,容易影响应用QPS和RT",
    "solution":"",
    "summary_format":""
}

highretran={
    "category":"NET",
    "level":"warning",
    "name":"网络高重传检查",
    "desc":"检查一天内高网络重传时间点,高网络重传可能导致应用异常",
    "solution":"",
    "summary_format":""
}

highcgroup={
    "category":"MISC",
    "level":"warning",
    "name":"cgroup数量高检查",
    "desc":"cgroup数量过大容易造成长时间关中断导致RT高和sys高",
    "solution":"",
    "summary_format":""
}

cfsquota={
    "category":"CPU",
    "level":"critical",
    "name":"cfs quota打开检查",
    "desc":"3.10内核打开cfsquota存在稳定性风险",
    "solution":"",
    "summary_format":""
}

small_pid_max={
    "category":"CPU",
    "level":"warning",
    "name":"pid_max设置检查",
    "desc":"较小pid_max容易导致创建新进程失败和ssh失联",
    "solution":"",
    "summary_format":"该机器任务数量为%s, pid_max=%s设置过小容易导致创建新进程失败和ssh失联，建议把机器的/proc/sys/kernel/pid_max的值调大，范围为[301,4194304]\n"
}

min_free_kbytes={
    "category":"MEM",
    "level":"warning",
    "name":"内存水线设置检",
    "desc":"较小内存水线,容易导致频繁的directreclaim和load高风险",
    "solution":"",
    "summary_format":"该机器min_free_kbytes=%skB设置过小容易频繁directreclaim,建议调整该参数为系统总内存大小的1-3%%\n"
}

cpuset_mems_inconsist={
    "category":"MEM",
    "level":"warning",
    "name":"NUMA设置检查",
    "desc":"打开NUMA后需要设置对应cpuset.mems,否则可能会存在节点OOM的风险",
    "solution":"",
    "summary_format":"存在某些cpuset cgroup的cpuset.mems设置和根组不相同，可能会存在节点OOM的风险\n"
}

mount_option={
    "category":"IO",
    "level":"critical",
    "name":"文件系统mount参数检查",
    "desc":"文件系统mount参数存在一些不兼容组合导致系统异常",
    "solution":"",
    "summary_format":"dioread_nolock和nodelalloc不能同时使用,建议修改mount的挂载参数\n"
}

tcp_fack={
    "category":"NET",
    "level":"warning",
    "name":"tcp_fack设置检查",
    "desc":"",
    "solution":"",
    "summary_format":"/proc/sys/net/ipv4/tcp_fack 推荐设置为1\n"
}

tcp_recovery={
    "category":"NET",
    "level":"warning",
    "name":"tcp_recovery设置检查",
    "desc":"",
    "solution":"",
    "summary_format":"/proc/sys/net/ipv4/tcp_recovery 推荐设置为1\n"
}

tcp_tw_timeout={
    "category":"NET",
    "level":"warning",
    "name":"tcp_tw_timeout设置检查",
    "desc":"",
    "solution":"",
    "summary_format":"/proc/sys/net/ipv4/tcp_tw_timeout 推荐设置为3\n"
}

tcp_tw_reuse={
    "category":"NET",
    "level":"warning",
    "name":"tcp_tw_reuse设置检查",
    "desc":"",
    "solution":"",
    "summary_format":"/proc/sys/net/ipv4/tcp_tw_reuse 推荐设置为1\n"
}

tcp_tw_recycle={
    "category":"NET",
    "level":"warning",
    "name":"tcp_tw_recycle设置检查",
    "desc":"表示开启TCP连接中TIME_WAIT sockets的快速回收",
    "solution":"",
    "summary_format":"/proc/sys/net/ipv4/tcp_tw_recycle 推荐设置为0\n"
}

tcp_sack={
    "category":"NET",
    "level":"warning",
    "name":"tcp_sack设置检查",
    "desc":"SACK 优化重传性能",
    "solution":"建议开启，在高延迟的连接中，SACK对于有效利用所有可用带宽尤其重要",
    "summary_format":"/proc/sys/net/ipv4/tcp_sack 推荐设置为1\n"
}

ip_early_demux={
    "category":"NET",
    "level":"critical",
    "name":"ip_early_demux设置检查",
    "desc":"3.10以前版本存在与该参数相关的宕机,需要关闭该参数",
    "solution":"",
    "summary_format":"/proc/sys/net/ipv4/ip_early_demux=%s,容易触发内核一个rcu的use after free的宕机BUG\n"
}

ibrs_enabled={
    "category":"MISC",
    "level":"warning",
    "name":"ibrs_enabled设置检查",
    "desc":"设置ibrs_enabled会导致性能损耗",
    "solution":"",
    "summary_format":"该机器设置ibrs_enabled导致性能损耗,建议关闭\n"
}

ibpb_enabled={
    "category":"MISC",
    "level":"warning",
    "name":"ibpb_enabled设置检查",
    "desc":"设置ibpb_enabled会导致性能损耗",
    "solution":"",
    "summary_format":"该机器设置ibpb_enabled导致性能损耗,建议关闭\n"
}

missed_hotfix={
    "category":"HOTFIX",
    "level":"warning",
    "name":"缺失hotfix检查",
    "desc":"缺失关键hotfix会存在稳定性风险",
    "solution":"",
    "summary_format":"该机器未部署缺省hotfix列表,建议安装这些重要的hotfix:%s\n"
}

conflict_hotfix={
    "category":"HOTFIX",
    "level":"warning",
    "name":"hotfix冲突检查",
    "desc":"hotfix冲突会导致hotfix不生效存在稳定性风险",
    "solution":"",
    "summary_format":"该机器部署如下hotfix存在冲突:%s\n"
}

nmi_backtrace = {
    "category":"NMI",
    "level":"critical",
    "name":"NMI响应检测",
    "desc":"若CPU没有响应NMI中断,则此CPU可能有硬件问题",
    "solution":"",
    "summary_format":"存在CPU:%s没有响应NMI中断，请检查CPU硬件\n"
}

microcode = {
    "category":"MICROCODE",
    "level":"critical",
    "name":"微码版本检测",
    "desc":"版本过低的微码在指定机型上会存在page faults或Machine Check问题",
    "solution":"",
    "summary_format":"版本过低的微码在指定机型上会存在page faults或Machine Check等宕机\n"
}

softlockup_panic = {
    "category":"SCHED",
    "level":"critical",
    "name":"softlockup_panic开关检测",
    "desc":"检测softlockup_panic是否关闭",
    "solution":"关闭softlockup_panic，sudo echo 0 > /proc/sys/kernel/softlockup_panic",
    "summary_format":"该机器softlockup_panic打开，容易造成频繁宕机，建议关闭\n"
}

hung_task_panic = {
    "category":"SCHED",
    "level":"critical",
    "name":"hung_task_panic开关检测",
    "desc":"检测hung_task_panic是否关闭",
    "solution":"关闭hung_task_panic，sudo echo 0 > /proc/sys/kernel/hung_task_panic",
    "summary_format":"该机器hung_task_panic打开，容易造成频繁宕机，建议关闭\n"
}

panic_on_oom = {
    "category":"MEM",
    "level":"critical",
    "name":"panic_on_oom开关检测",
    "desc":"检测panic_on_oom是否关闭",
    "solution":"关闭panic_on_oom，sudo echo 0 > /proc/sys/vm/panic_on_oom",
    "summary_format":"该机器panic_on_oom打开，容易造成频繁宕机，建议关闭\n"
}

