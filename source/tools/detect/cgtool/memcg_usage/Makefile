newdirs += .
csrcs += $(filter-out $(wildcard *.bpf.c), $(wildcard *.c))
bpfsrcs += $(wildcard *.bpf.c)

CFLAGS += -static

target = memcg_usage

include $(SRC)/mk/bpf.mk
