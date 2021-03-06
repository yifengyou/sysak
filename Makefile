# Automatically generated by configure - do not modify
#KERNEL_VERSION = 4.19.91-23.4.an8.x86_64
#OBJPATH = /root/sysak.git/out
#BUILD_KERNEL_MODULE = YES
#BUILD_LIBBPF = YES
#TARGET_LIST = /root/sysak.git/source/tools/inject/taskctl /root/sysak.git/source/tools/combine/ossre_client /root/sysak.git/source/tools/combine/btf /root/sysak.git/source/tools/monitor/mservice /root/sysak.git/source/tools/monitor/tracesig /root/sysak.git/source/tools/monitor/mon_connect /root/sysak.git/source/tools/monitor/sched/runqslower /root/sysak.git/source/tools/monitor/sched/schedmoni /root/sysak.git/source/tools/monitor/sched/nosched /root/sysak.git/source/tools/monitor/sched/runlatency /root/sysak.git/source/tools/monitor/sched/schedtrace /root/sysak.git/source/tools/monitor/mmaptrace /root/sysak.git/source/tools/test/cc_test /root/sysak.git/source/tools/test/c_test /root/sysak.git/source/tools/test/go_test /root/sysak.git/source/tools/test/bpf_test /root/sysak.git/source/tools/test/sh_test /root/sysak.git/source/tools/detect/softirq /root/sysak.git/source/tools/detect/netinfo /root/sysak.git/source/tools/detect/pagescan /root/sysak.git/source/tools/detect/iofsstat /root/sysak.git/source/tools/detect/memgraph /root/sysak.git/source/tools/detect/sysconf /root/sysak.git/source/tools/detect/sysconf/confcheck /root/sysak.git/source/tools/detect/fcachetop /root/sysak.git/source/tools/detect/sysmonitor /root/sysak.git/source/tools/detect/net_diag/netinfo /root/sysak.git/source/tools/detect/net_diag/pktdrop /root/sysak.git/source/tools/detect/net_diag/rtrace /root/sysak.git/source/tools/detect/net_diag/udpping /root/sysak.git/source/tools/detect/net_diag/PingTrace /root/sysak.git/source/tools/detect/net_diag/tcpping /root/sysak.git/source/tools/detect/loadtask /root/sysak.git/source/tools/detect/memleak /root/sysak.git/source/tools/detect/skcheck /root/sysak.git/source/tools/detect/cpuirq /root/sysak.git/source/tools/detect/iosdiag /root/sysak.git/source/tools/detect/irqoff /root/sysak.git/source/tools/detect/cgtool /root/sysak.git/source/tools/detect/oomcheck /root/sysak.git/source/tools/detect/runqlat /root/sysak.git/source/tools/detect/taskstate /root/sysak.git/source/tools/detect/surftrace /root/sysak.git/source/tools/detect/runqlen /root/sysak.git/source/tools/detect/appscan /root/sysak.git/source/tools/detect/cpu_flamegraph /root/sysak.git/source/tools/detect/cpuirq /root/sysak.git/source/tools/detect/sysmonitor /root/sysak.git/source/tools/detect/cpu_flamegraph 


ifneq ($(wildcard config-host.mak),)
include config-host.mak
else
config-host.mak:
	@echo "Please call configure before running make!"
	@exit 1
endif

SRC := $(shell pwd)/source

OBJ_LIB_PATH := $(OBJPATH)/.sysak_compoents/lib/$(KERNEL_VERSION)
OBJ_TOOLS_ROOT := $(OBJPATH)/.sysak_compoents/tools
OBJ_TOOLS_PATH := $(OBJPATH)/.sysak_compoents/tools/$(KERNEL_VERSION)
SYSAK_RULES := .sysak.rules

export KERNEL_VERSION
export SRC
export OBJPATH
export OBJ_LIB_PATH
export OBJ_TOOLS_ROOT
export OBJ_TOOLS_PATH
export SYSAK_RULES
export BUILD_KERNEL_MODULE
export BUILD_LIBBPF
export EXTRA_LDFLAGS
export TARGET_LIST

.PHONY: all lib tools binary install $(TARGET_LIST)
all: config-host.mak $(OBJ_LIB_PATH) $(OBJ_TOOLS_PATH) lib tools binary

lib:
	make -C $(SRC)/lib

tools: $(TARGET_LIST)

$(TARGET_LIST):
	make -C $@ -j

binary:
	$(CC) -o $(SRC)/sysak $(SRC)/sysak.c
	cp $(SRC)/sysak $(OBJPATH)/
	chmod +x $(OBJPATH)/sysak
	chmod +x $(OBJPATH)/.sysak_compoents/tools/* -R

.PHONY: clean clean_middle
clean:
	make -C $(SRC)/lib clean
	rm -rf $(OBJPATH)

clean_middle:
	make -C $(SRC)/lib clean
	rm -rf $(OBJPATH)/*.o

$(OBJ_LIB_PATH):
	mkdir -p $(OBJ_LIB_PATH)

$(OBJ_TOOLS_PATH):
	mkdir -p $(OBJ_TOOLS_PATH)

install:
	cp $(OBJPATH)/sysak /usr/local/sbin/
	cp $(OBJPATH)/.sysak_compoents /usr/local/sbin/ -rf
	mkdir -p /etc/sysak
	mkdir -p /var/log/sysak
	cp $(OBJPATH)/.sysak_compoents/tools/monitor/sysakmon.conf /etc/sysak/

uninstall:
	rm -rf /etc/sysak
	rm -rf /usr/local/sbin/sysak
	rm -rf /usr/local/sbin/.sysak_compoents
