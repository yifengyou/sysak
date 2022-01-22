newdirs += .
csrcs += $(filter-out $(wildcard *.bpf.c), $(wildcard *.c))
bpfsrcs += $(wildcard *.bpf.c)

CFLAGS += -static

target = cpuacct_load

include $(SRC)/mk/bpf.mk
