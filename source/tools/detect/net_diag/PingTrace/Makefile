LDFLAGS += -l:liblog4cpp.a -lncurses -lz -pthread -ltinfo -ldl
CFLAGS += -std=c++11 -static
INCLUDES += -Isrc/ -Isrc/bpf -I$(SRC)/lib/internal/ebpf/libbpf/src

newdirs := $(shell find src/ -type d)
cppsrcs := $(shell find ./src -name "*.cc")
bpfsrcs := $(wildcard src/bpf_prog/*.bpf.c)
target := pingtrace

include $(SRC)/mk/ccbpf.mk
