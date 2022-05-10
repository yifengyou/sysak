# 龙蜥社区sysak项目学习

```
fork from https://gitee.com/anolis/sysak
just for fun~
```

## 目录


* [跑起来](docs/跑起来.md)
    * [环境搭建](docs/跑起来/环境搭建.md)
    * [构建rpm包](docs/跑起来/构建rpm包.md)
* [构建工具](docs/构建工具.md)
    * [configure](docs/构建工具/configure.md)
    * [make](docs/构建工具/make.md)
* [工具集](docs/工具集.md)
    * [cpu_flamegraph](docs/工具集/cpu_flamegraph.md)
    * [appscan](docs/工具集/appscan.md)
    * [runqlen](docs/工具集/runqlen.md)
    * [surftrace](docs/工具集/surftrace.md)
    * [taskstate](docs/工具集/taskstate.md)
    * [runqlat](docs/工具集/runqlat.md)
    * [oomcheck](docs/工具集/oomcheck.md)
    * [cgtool](docs/工具集/cgtool.md)
    * [irqoff](docs/工具集/irqoff.md)
    * [iosdiag](docs/工具集/iosdiag.md)
    * [cpuirq](docs/工具集/cpuirq.md)
    * [skcheck](docs/工具集/skcheck.md)
    * [memleak](docs/工具集/memleak.md)
    * [loadtask](docs/工具集/loadtask.md)
    * [tcpping](docs/工具集/tcpping.md)
    * [PingTrace](docs/工具集/PingTrace.md)
    * [udpping](docs/工具集/udpping.md)
    * [rtrace](docs/工具集/rtrace.md)
    * [pktdrop](docs/工具集/pktdrop.md)
    * [netinfo](docs/工具集/netinfo.md)
    * [sysmonitor](docs/工具集/sysmonitor.md)
    * [fcachetop](docs/工具集/fcachetop.md)
    * [confcheck](docs/工具集/confcheck.md)
    * [sysconf](docs/工具集/sysconf.md)
    * [memgraph](docs/工具集/memgraph.md)
    * [iofsstat](docs/工具集/iofsstat.md)
    * [pagescan](docs/工具集/pagescan.md)
    * [netinfo](docs/工具集/netinfo.md)
    * [softirq](docs/工具集/softirq.md)
    * [sh_test](docs/工具集/sh_test.md)
    * [bpf_test](docs/工具集/bpf_test.md)
    * [go_test](docs/工具集/go_test.md)
    * [c_test](docs/工具集/c_test.md)
    * [cc_test](docs/工具集/cc_test.md)
    * [mmaptrace](docs/工具集/mmaptrace.md)
    * [schedtrace](docs/工具集/schedtrace.md)
    * [runlatency](docs/工具集/runlatency.md)
    * [nosched](docs/工具集/nosched.md)
    * [schedmoni](docs/工具集/schedmoni.md)
    * [runqslower](docs/工具集/runqslower.md)
    * [mon_connect](docs/工具集/mon_connect.md)
    * [tracesig](docs/工具集/tracesig.md)
    * [mservice](docs/工具集/mservice.md)
    * [btf](docs/工具集/btf.md)
    * [ossre_client](docs/工具集/ossre_client.md)
    * [taskctl](docs/工具集/taskctl.md)



## 原仓库README.md


```
what is sysAK

sysAK (system analyse kit) is a toolbox contains useful tools for linux SRE,
such as problem diagnosing, events monitoring/tracing, and operating of system and service.
These tools come from everyday work experience and other good tools from Alibaba,
like diagnose-tools, ossre, NX etc.

It is distributed under the Mulan Permissive Software License，Version 2 - see the
accompanying LICENSE file for more details.
And keep the origin License for the lib dir -include kernel modules and libbpf, which is compatible
with usermode tools.



Quick start to use sysAK:
1) ./configure
2) make
3) ./out/sysak

See more info about sysAK tools at doc/
```


---
