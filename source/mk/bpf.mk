CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(SRC)/lib/internal/ebpf/tools/bpftool
APPS_DIR := $(abspath .)
CFLAGS := -g -O2 -Wall
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LIBBPF_OBJ := $(OBJ_LIB_PATH)/libbpf.a

ifeq ($(KERNEL_DEPEND), Y)
OUTPUT := $(OBJ_TOOLS_PATH)
else
OUTPUT := $(OBJ_TOOLS_ROOT)
endif

INCLUDES := -I$(OBJPATH) -I$(SRC)/lib/internal/ebpf -I$(OUTPUT) -I$(OBJ_LIB_PATH) -I$(SRC)/lib/internal/ebpf/libbpf/include/uapi 

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

cobjs := $(foreach n, $(cobject), $(OBJPATH)/$(n))
bpfobjs := $(foreach n, $(bpfobject), $(OBJPATH)/$(n))
bpfskel := $(patsubst %.bpf.o, %.skel.h, $(bpfobjs))

$(target): $(cobjs) $(bpfskel) $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $^ -lelf -lz -o $(OUTPUT)/$@
	echo $(target):$(DEPEND) >> $(OUTPUT)/$(SYSAK_RULES)
$(cobjs): $(cobject)

$(cobject): %.o : %.c $(bpfskel)
	$(call msg,CC,$@) 
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $(OBJPATH)/$@

$(bpfskel): %.skel.h : %.bpf.o $(bpfobjs)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(bpfobjs): $(bpfobject)

$(bpfobject) : %.o : %.c
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $(OBJPATH)/$@
	$(Q)$(LLVM_STRIP) -g $(OBJPATH)/$@ # strip useless DWARF info

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
# .SECONDARY:

