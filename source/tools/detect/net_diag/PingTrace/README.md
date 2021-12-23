# PingTrace
PingTrace是一个基于eBPF实现的网络延迟探测定界工具，该工具实现了一个基于ICMP回显(ICMP_ECHO 和 ICMP_ECHOREPLY)协议的网络延迟探测协议，通过发送和解析探测报文来定位报文在不同传输阶段的延迟信息。
## 构建
### 环境依赖

#### 安装log4cpp库

```
下载链接： https://sourceforge.net/projects/log4cpp/files/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.3.tar.gz/download
tar -xzf log4cpp-1.1.3.tar.gz -C ./
cd log4cpp && ./configure && make && make install
```

#### 安装rapidjson库

```
git clone https://github.com/Tencent/rapidjson.git
git submodule update --init
mkdir build && cd build && cmake .. && make install
```

#### 安装CLI11库

```
git clone https://github.com/CLIUtils/CLI11.git
git checkout 34c4310d9907f6a6c2eb5322fa7472474800577c
git submodule update --init
mkdir build && cd build && cmake .. && make install
```

### 编译
```
make -j <NR_CPUS>
```
## 运行
要运行PingTrace，请保证如下位置之一有内核btf相关文件：
- /sys/kernel/btf/vmlinux
- /boot/vmlinux-<kernel_release>
- /lib/modules/<kernel_release>/vmlinux-<kernel_release>
- /lib/modules/<kernel_release>/build/vmlinux
- /usr/lib/modules/<kernel_release>/kernel/vmlinux
- /usr/lib/debug/boot/vmlinux-<kernel_release>
- /usr/lib/debug/boot/vmlinux-<kernel_release>.debug
- /usr/lib/debug/lib/modules/<kernel_release>/vmlinux

## 使用
### 命令行参数
```
Usage: pingtrace [OPTIONS]

Options:
  -v,--version                显示版本号
  -h,--help                   帮助信息
  -s,--server                 以server模式运行
  -c,--client ip              以client模式运行
  -C,--count UINT             探测报文数量，默认无限
  -i interval_us              以微秒为单位，报文发送间隔时间
  -t UINT                     以秒为单位，程序运行时间
  -m,--maxdelay us            以微秒为单位，判定为毛刺的阈值。只有超过该值的报文数据才会被记录下来，默认为0
  -b INT=556                  发送探测报文的大小，至少144字节
  --log TEXT=./pingtrace.log  日志文件名称
  --logsize INT               日志文件最大占用磁盘空间
  --logbackup INT=3           日志文件最多备份数量
  --mode auto/pingpong/compact
                              PingTrace运行模式
  -o,--output image/json/log/imagelog
                              PingTrace数据输出格式
  -n,--namespace              探测与net namespace相关的信息
  --nslocal                   在探测net namespace相关信息时，告知PingTrace client和server运行在同一host上，以避免获取到冗余数据
  --userid UINT               在探测net namespace相关信息时，为不同Host指定不同userid，以帮助PingTrace识别和修正不同Host上时间不同步问题
  --debug                     打印相关debug信息，主要为libbpf信息
```
### 使用示例
启动server：
```
./pingtrace -s
```
启动server，10s后自动关闭：
```
./pingtrace -s -t 10
```
启动client，ping本机，默认每秒发一个包：
```
./pingtrace -c 127.0.0.1
```
启动client，ping本机，每100ms发送一个包：
```
./pingtrace -c 127.0.0.1 -i 100000
```
启动client，ping本机，共发送100个包，设置运行时间为100s:
```
./pingtrace -c 127.0.0.1 -t 100 -C 100
```
启动client，ping本机，超过1ms的报文算作毛刺，结果记录到log文件中：
```
./pingtrace -c 127.0.0.1 -m 1000 -o log
```
启动client，ping本机，超过1ms的报文算作毛刺，结果记录到log文件中，并修改log的名称为result.log，且日志备份数量设置为2：
```
./pingtrace -c 127.0.0.1 -m 1000 -o log --log result.log --logbackup=2
```
启动client，ping本机，超过1ms的报文算作毛刺，结果记录到log文件中，并以图形界面展示：
```
./pingtrace -c 127.0.0.1 -m 1000 -o imagelog
```