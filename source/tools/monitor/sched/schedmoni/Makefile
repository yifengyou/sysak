
newdirs := $(shell find ./ -type d)

bpfsrcs := $(wildcard bpf/*.bpf.c)
csrcs := $(wildcard *.c)
target := schedmoni

LDFLAGS += -pthread
include $(SRC)/mk/bpf.mk
