newdirs += .
csrcs += $(filter-out $(wildcard *.bpf.c), $(wildcard *.c))
bpfsrcs += $(wildcard *.bpf.c)

CFLAGS += -static

target = latency

include $(SRC)/mk/bpf.mk
