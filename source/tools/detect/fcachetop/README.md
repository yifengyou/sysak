# fcachetop
统计系统当前已打开文件的page cache占用情况以及cache命中率

# sysak打包
在编译sysak的之前，需要在执行configure配置的时候加上--enable-target-fcachetop才能打包进sysak

# 使用
## 参数说明
```
usage: fcachetop.py [-h] [-f FILE] [-i INTERVAL] [-T TOP] [-v]

Statistics the file page cached.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Statistics the file pages cached from specified file.
  -i INTERVAL, --interval INTERVAL
                        Display the file pages cached per N seconds(CTRL+C
                        exit).
  -T TOP, --top TOP     Display the file pages cached of TopN (default Top
                        10).
  -v, --verbo           Display the full path of the file(By default, when the
                        file path exceeds 48 characters, the full path of the
                        file is hidden).

e.g.
./fcachetop             Display the file pages cached of Top10
./fcachetop -f /xxx/file
                        Statistics the file pages cached for '/xxx/file'
./fcachetop -i 2        Display the file pages cached per N seconds(CTRL+C exit)
./fcachetop -T 30       Display the file pages cached of Top30
```
## 使用示例
```
./fcachetop.py #统计一次正打开文件的pagecache占用情况（没有指定-T参数，默认只显示pagecache大小前top10的文件）

The top10 Max cached open files:
Name                                            Cached pages/size       Total pages     Hit percent     Comm:Pid
/var/log/jour...6b05d-0005dc529a33350d.journal  16896/66.00MB           18432           91.67%          syslog-ng:37270
/var/log/jour...f3ac2-0005dc3046c2f0f8.journal  16878/65.93MB           18432           91.57%          syslog-ng:37270
/var/log/jour...26d50-0005dc3efde06626.journal  16871/65.90MB           18432           91.53%          syslog-ng:37270
/var/log/jour...04ba3-0005dc352f25db7c.journal  16864/65.88MB           18432           91.49%          syslog-ng:37270
/var/log/jour...37e1d-0005dc43e5e6b981.journal  16860/65.86MB           18432           91.47%          syslog-ng:37270
/var/log/jour...c0849-0005dc219110f1fa.journal  16852/65.83MB           18432           91.43%          syslog-ng:37270
/var/log/jour...e29ed-0005dc2b5f3649be.journal  16851/65.82MB           18432           91.42%          syslog-ng:37270
/var/log/jour...48ec5-0005dc48cc13376b.journal  16844/65.80MB           18432           91.38%          syslog-ng:37270
/var/log/jour...d1925-0005dc2677f2db59.journal  16843/65.79MB           18432           91.38%          syslog-ng:37270
/var/log/jour...59f90-0005dc4db42a2abc.journal  16840/65.78MB           18432           91.36%          syslog-ng:37270
/var/log/jour...af777-0005dc1ca9f8839c.journal  16837/65.77MB           18432           91.35%          syslog-ng:37270
Total cached 3.01GB for all open files
```
Name：文件名称，默认情况下当文件路径长度大于48个字符会隐藏，可指定-v参数显示文件全路径
Cached pages/size：文件目前占用的page页数/大小
Total pages：当文件全部命中cache时，需要的page总数
Hit percent：page cache命中率
Comm:Pid：进程名：进程ID

```
./fcachetop.py -T 20 -i 1 #间隔1秒统计一次正打开文件的pagecache占用情况（指定-i参数，会持续统计，知道ctrl+c退出，指定-T 20，展示前top20的文件）

The top20 Max cached open files:
Name                                            Cached pages/size       Total pages     Hit percent     Comm:Pid
/var/log/jour...6b05d-0005dc529a33350d.journal  16896/66.00MB           18432           91.67%          syslog-ng:37270
/var/log/jour...f3ac2-0005dc3046c2f0f8.journal  16878/65.93MB           18432           91.57%          syslog-ng:37270
/var/log/jour...26d50-0005dc3efde06626.journal  16871/65.90MB           18432           91.53%          syslog-ng:37270
/var/log/jour...04ba3-0005dc352f25db7c.journal  16864/65.88MB           18432           91.49%          syslog-ng:37270
/var/log/jour...37e1d-0005dc43e5e6b981.journal  16860/65.86MB           18432           91.47%          syslog-ng:37270
/var/log/jour...c0849-0005dc219110f1fa.journal  16852/65.83MB           18432           91.43%          syslog-ng:37270
/var/log/jour...e29ed-0005dc2b5f3649be.journal  16851/65.82MB           18432           91.42%          syslog-ng:37270
/var/log/jour...48ec5-0005dc48cc13376b.journal  16844/65.80MB           18432           91.38%          syslog-ng:37270
/var/log/jour...d1925-0005dc2677f2db59.journal  16843/65.79MB           18432           91.38%          syslog-ng:37270
/var/log/jour...59f90-0005dc4db42a2abc.journal  16840/65.78MB           18432           91.36%          syslog-ng:37270
/var/log/jour...af777-0005dc1ca9f8839c.journal  16837/65.77MB           18432           91.35%          syslog-ng:37270
/var/log/jour...15c74-0005dc3a1635c914.journal  16818/65.70MB           18432           91.24%          syslog-ng:37270
/var/log/jour...9e6b0-0005dc17c46c9cd0.journal  16802/65.63MB           18432           91.16%          syslog-ng:37270
/var/log/jour...38767-0005db674394a250.journal  13942/54.46MB           18432           75.64%          syslog-ng:37270
/var/log/jour...8dc3c-0005db7fc43e8df1.journal  13903/54.31MB           18432           75.43%          syslog-ng:37270
/var/log/jour...49885-0005db6c2a83cf57.journal  13888/54.25MB           18432           75.35%          syslog-ng:37270
/var/log/jour...5a955-0005db7111d7a0e6.journal  13888/54.25MB           18432           75.35%          syslog-ng:37270
/var/log/jour...afa50-0005dbd320e74823.journal  13881/54.22MB           18432           75.31%          syslog-ng:37270
/var/log/jour...7cb00-0005db7add3d2cb1.journal  13862/54.15MB           18432           75.21%          syslog-ng:37270
/var/log/jour...8d5e1-0005dc12dd077fd9.journal  13849/54.10MB           18432           75.14%          syslog-ng:37270
/var/log/jour...e2c9d-0005dbe1d58d4561.journal  13844/54.08MB           18432           75.11%          syslog-ng:37270
Total cached 3.01GB for all open files(ctrl+c exit) #这里显示统计到正打开的总文件缓存占用情况
```

