CLANG ?= clang 
LLVM_STRIP ?= llvm-strip 
BPFTOOL ?= $(SRC)/lib/internal/ebpf/tools/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LIBBPF_OBJ := $(OBJ_LIB_PATH)/libbpf.a


CFLAGS = -g -O2 -Wall -fPIC

INCLUDES = -I$(OBJPATH) -I$(SRC)/lib/internal/ebpf -I$(SRC)/lib/internal/ebpf/libbpf/include -I$(SRC)/lib/internal/ebpf/libbpf/include/uapi -I$(OBJ_LIB_PATH) -I.


newdirs := $(shell find ./ -type d)
bpfsrcs := rtrace.bpf.c
csrcs := rtrace.c utils/btf.c utils/disasm.c utils/insn.c utils/object.c

newdirs := $(addprefix $(OBJPATH)/, $(newdirs))
cobjs := $(patsubst %.c, %.o, $(csrcs))
target_cobjs := $(foreach n, $(cobjs), $(OBJPATH)/$(n))

bpfobjs := $(patsubst %.c, %.o, $(bpfsrcs))
target_bpfobjs := $(foreach n, $(bpfobjs), $(OBJPATH)/$(n))

bpfskel := $(patsubst %.bpf.o, %.skel.h, $(target_bpfobjs))

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'                                   \
		"$(1)"                                            \
		"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"       \
		"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif


librtrace: $(OBJ_LIB_PATH)/librtrace.a

$(OBJ_LIB_PATH)/librtrace.a: $(target_cobjs)
	$(Q) ar -rcs $@ $^

$(target_cobjs): $(cobjs)

$(cobjs): %.o : %.c $(bpfskel)
	$(call msg,CC,$@) 
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $(OBJPATH)/$@ 

$(bpfskel): %.skel.h : %.bpf.o $(target_bpfobjs)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(target_bpfobjs): $(bpfobjs)

$(bpfobjs) : %.o : %.c dirs
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $(OBJPATH)/$@ 
	$(Q)$(LLVM_STRIP) -g $(OBJPATH)/$@ # strip useless DWARF info

dirs:
	mkdir -p $(newdirs)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
# .SECONDARY:
