# tcpping
tcpping是一个基于eBPF实现的网络延迟探测定界工具，该工具实现了一个基于TCP协议的网络延迟探测协议，通过发送和解析探测报文来定位报文在不同传输阶段的延迟信息。
## 构建
### 环境依赖

#### libnet

```
libnet 源码：
目前程序中将源码编译成libnet.a放在lib路径下,链接到tcpping中
```

### 编译
```
./configure --enable-target-tcpping
./configure --enable-target-btf
sudo make
编译生成的二进制tcpping在out路径下, 在tcpping路径下已经放置了编译好的二进制文件
```
## 运行
要运行tcpping，请保证如下位置有内核btf相关文件：
- /sys/kernel/btf/vmlinux
- /boot/vmlinux-<kernel_release>
- /lib/modules/<kernel_release>/vmlinux-<kernel_release>
- /lib/modules/<kernel_release>/build/vmlinux
- /usr/lib/modules/<kernel_release>/kernel/vmlinux
- /usr/lib/debug/boot/vmlinux-<kernel_release>
- /usr/lib/debug/boot/vmlinux-<kernel_release>.debug
- /usr/lib/debug/lib/modules/<kernel_release>/vmlinux
- 程序中默认会优先在sysak中寻找

## 使用
### 命令行参数
```
Usage: tcpping [OPTIONS]

Options:

  -h,--help                   帮助信息
  -s,--source ip              源ip
  -d,--dest ip                目的ip
  -c,--package count          探测报文数量，默认无限
  -t,--interval_us            报文发送间隔时间(ms), 默认1ms
  -p,--source port            源端口，默认30330
  -q,--dest port              目的端口，默认80
  -o,--output image/json      -o **.json 指定路径输出json格式，不指定-o
			      控制台输出
  -u,--cpu affinity           指定cpu运行，默认cpu0, -1 不指定cpu
```
### 使用示例
```
sysak tcpping -s 11.160.62.45 -d 11.160.62.49 -c 10
```
发送10个报文，输出到控制台,结果如下
```
+-------------------tcp-trace---------------------+
| seq:    9                       unit:usec       |
|      +-------+        148  +---------------+    |
|      | local |  ---------> |   11.160.62.49|    |
|      +-------+             +---------------+    |
|        |    user    |                           |
|  ------------------------         +--------+    |
|        |            |             |        |    |
|      2 | trans layer|             |        |    |
|  ------------------------         |        |    |
|        |            |             |        |    |
|      6 |  ip layer  |     3       |        |    |
|        |-----------------         |        ^    |
|        |            |             v        |    |
|        |  dev layer |     1       |        |    |
|  ------|------------|----         |        |    |
|        v            |     134     |        |    |
|        |            +-------<-----+        |    |
|        +---------------->------------------+    |
|                                                 |
+-------------------------------------------------+
```
sysak tcpping -s 11.160.62.45 -d 11.160.62.49 -c 10 -o /tmp/tcpping.json
```
发送10个报文，输出到/tmp/tccping.json文件中
```
{
        "data": {
                "seq":  0,
                "t_trans":      8,
                "t_ip": 34,
                "r_remote":     302,
                "r_dev":        9,
                "r_ip": 24,
                "delta":        379
        },
        "data": {
                "seq":  1,
                "t_trans":      3,
                "t_ip": 10,
                "r_remote":     206,
                "r_dev":        1,
                "r_ip": 6,
                "delta":        228
        }
}
```
