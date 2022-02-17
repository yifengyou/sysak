# rtrace-drop

rtrace-drop是基于rtrace的网络丢包溯源诊断,能够有效地且精准地定位到网络丢包,并提供足量的数据信息。

rtrace-drop提供了模块化检测。


## 使用说明

```shell
rtrace_drop 0.1.0
Network packet drop traceability diagnosis

USAGE:
    rtrace-drop [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --config <config>         configuration file path
    -e, --exclude <exclude>...    Exclude packet loss points
        --gen <gen>               generate default configuration file
    -i, --include <include>...    Included drop points
    -l, --list <list>...          show all packet loss points
    -p, --period <period>         monitor program running cycle, defaule 1 second [default: 1]
```

### 参数说明

* `-e, --exclude`: 表示不诊断的丢包点
* `-i, --include`: 表示诊断的丢包点
* `-l, --list`: 查看当前支持诊断的丢包点
* `--config`: 配置文件
* `--gen`: 生成默认的配置文件
* `-p --period`: 监控程序的运行周期，默认1秒运行一次

注: `-e`的优先级高于`-i`

### 使用样例

#### 查看当前支持的丢包检测点

`sysak rtrace-drop -l`输出如下:

```
all                           
    l1                            
    l2                            
    l3                            
        iptables                      
            ipt_do_table                                [Not Support]
        conntrack                     
            ipv4_conntrack_in                           [Not Support]
            ipv4_conntrack_local                        [Not Support]
            ipv4_helper                                 [Not Support]
            ipv4_confirm                                [Not Support]
        fib                           
            fib_validate_source                         [Support: rp_filter]
    l4                            
        tcp                           
            tcp_conn_request                            [Support]
            tcp_v4_syn_recv_sock                        [Support]
            tcp_add_backlog                             [Support]
            __skb_checksum_complete                     [Support]
        udp                           
    mointor                       
        netlink                                 [Support: overrun]
        proc                          
            tcp_tw_recycle                              [Support]
```

#### 监控系统丢包

运行命令`sysak rtrace-drop --config <PATH>`, 即可诊断当前系统是否存在丢包及丢包原因。

#### 监控l4层丢包

运行命令`sysak rtrace-drop -i l4 --config <PATH>`

## 覆盖场景及检测原理

rtrace-drop将丢包点按照网络协议栈分成四个层次，分别是:
* l4层, 即传输层, 实现udp、tcp等网络丢包点的监控
* l3层, 即网络层, 实现ip网络丢包点的监控
* l2层, 即数据链路层, 实现中断等丢包点的监控
* l1层, 即物理层, 实现硬件丢包点的监控

需要注意的是每个层次还可嵌套子模块。如l4层，可新增udp或tcp丢包点监控模块。除了分成四个层次外，还包含一个特殊的模块，即monitor。monitor主要用来检查系统环境的配置是否正确及系统丢包统计参数。

### l4层

l4层包含tcp和udp两大模块。

#### tcp

tcp模块监控的丢包点有:

* tcp_conn_request: syn或accept队列满丢包
* tcp_v4_syn_recv_sock: accept队列满丢包
* tcp_add_backlog: backlog队列满丢包

1. tcp_conn_request

支持检测半连接队列满或全连接队列满导致的丢包, 并给出队列长度信息。

* 判断syn队列是否满的条件: `((struct inet_connection_sock *)sk).icsk_accept_queue.qlen.counter > sk.sk_max_ack_backlog`

* 判断accept队列是否满的条件: `sk.sk_ack_backlog > sk.sk_max_ack_backlog`

```toml
[[function]]
name = "tcp_conn_request"
params = ["basic"]
exprs = ["sk.sk_ack_backlog", "sk.sk_max_ack_backlog", "((struct inet_connection_sock *)sk).icsk_accept_queue.qlen.counter"]
```

2. tcp_v4_syn_recv_sock

支持检测accept队列满导致的丢包,并给出队列长度信息。

* 判断accept队列是否满:`sk.sk_ack_backlog > sk.sk_max_ack_backlog`

```toml
[[function]]
name = "tcp_v4_syn_recv_sock"
params = ["basic"]
exprs = ["sk.sk_ack_backlog", "sk.sk_max_ack_backlog"]
```

3. tcp_add_backlog

支持检测backlog队列满导致的丢包,并给出当前rcvbuf和sndbuf信息。

* 判断backlog队列满:sk->sk_backlog.len + sk.sk_backlog.rmem_alloc > sk.sk_rcvbuf + sk.sk_sndbuf + HEADROOM

```toml
[[function]]
name = "tcp_add_backlog"
params = ["basic"]
expr = ["sk.sk_rcvbuf", "sk.sk_sndbuf", "sk.sk_backlog.len", "sk.sk_backlog.rmem_alloc"]
```

4. tcp_rcv_established

支持检测csum错误导致的丢包。

* 通过获取__skb_checksum_complete的返回值, 丢包条件是:`ret != 0`

```toml
[[function]]
name = "tcp_rcv_established"
params = ["basic"]

[[function]]
name = "__skb_checksum_complete"
params = ["basic", "kretprobe"]
```

#### UDP



### l3层


目前支持iptables、conntrack和FIB模块的丢包检查。

#### iptables

iptables模块丢包检查，目前支持：

* ipt_do_table: 跟踪iptable规则导致的丢包


1. ipt_do_table

* `kretprobe = NF_DROP`时，表示iptables某条drop规则丢弃了改包
* 额外数据信息: 表信息、链信息;

```toml
[[function]]
name = "ipt_do_table"
skb = 1
params = ["basic", "kretprobe"]
exprs = ["state.net.ipv4.iptable_filter", "state.net.ipv4.iptable_mangle", "state.net.ipv4.iptable_raw", "state.net.ipv4.arptable_filter", "state.net.ipv4.iptable_security", "state.net.ipv4.nat_table", "table", "state.hook"]
```

#### conntrack

conntrack模块丢包检查, 目前支持:

* ipv4_conntrack_in
* ipv4_conntrack_local
* ipv4_helper
* ipv4_confirm

#### FIB(Forwarding Infomation Base)

FIB模块丢包检查,目前支持:

* fib_validate_source

1. fib_validate_source: 当`kretprobe < 0`时,表示丢包:

* `kretprobe = -18`时,表示rp_filter过滤丢包
    

```toml
[[fib_validate_source]]
name = "fib_validate_source"
params = ["basic", "kretprobe"]
```

### monitor模块

主要是监控系统自带的统计参数及系统环境参数。比如, 利用netlink监测由硬件的ring buffer溢出导致的丢包数。

#### netlink

利用netlink检测丢包, 目前支持:

* overrun: 表示由于网卡硬件缓冲区不足导致的丢包数;

#### proc

查看proc目录下是否存在可能导致丢包的配置, 目前支持:

* tcp_tw_recycle: 回收TIME-WAIT状态的socket。在nat场景下, 一般建议关闭。注:4.12版本后该参数已经被移除

<!-- https://tencentcloudcontainerteam.github.io/tke-handbook/damn/lost-packets-once-enable-tcp-tw-recycle.html -->




