CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(SRC)/lib/internal/ebpf/tools/bpftool
APPS_DIR := $(abspath .)
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LIBBPF_OBJ += $(OBJ_LIB_PATH)/libbpf.a

ifeq ($(KERNEL_DEPEND), Y)
OUTPUT := $(OBJ_TOOLS_PATH)
else
OUTPUT := $(OBJ_TOOLS_ROOT)
endif

CFLAGS += $(EXTRA_CLFAGS) -g -O2 -Wall
LDFLAGS += $(EXTRA_LDFLAGS)
INCLUDES += $(EXTRA_INCLUDES) -I$(OBJPATH) -I$(SRC)/lib/internal/ebpf -I$(OUTPUT) -I$(OBJ_LIB_PATH) -I$(SRC)/lib/internal/ebpf/libbpf/include/uapi 

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

newdirs := $(addprefix $(OBJPATH)/, $(newdirs))

cobjs := $(patsubst %.c, %.o, $(csrcs))
target_cobjs := $(foreach n, $(cobjs), $(OBJPATH)/$(n))

bpfobjs := $(patsubst %.c, %.o, $(bpfsrcs))
target_bpfobjs := $(foreach n, $(bpfobjs), $(OBJPATH)/$(n))

bpfskel := $(patsubst %.bpf.o, %.skel.h, $(target_bpfobjs))

$(target): $(target_cobjs) $(bpfskel) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $^ -lelf -lz -o $(OUTPUT)/$@ $(LDFLAGS)
	echo $(target):$(DEPEND) >> $(OUTPUT)/$(SYSAK_RULES)
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

