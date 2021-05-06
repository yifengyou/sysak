OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
# BPFTOOL ?= $(abspath utils/bpftool)
BPFTOOL ?= $(SRC)/lib/internal/ebpf/tools/bpftool
# LIBBPF_SRC := $(abspath libbpf/src)
LIBBPF_OBJ := $(OBJ_LIB_PATH)/libbpf.a
APPS_DIR := $(abspath .)
INCLUDES := -I$(SRC)/lib/internal/ebpf/vmlinux -I$(OUTPUT) -I$(SRC)/lib/internal/ebpf/libbpf/include/uapi
CFLAGS := -g -O2 -Wall
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
endif

APPS = $(basename $(basename $(notdir $(wildcard *.bpf.c))))

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

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	mkdir -p $@

# build libbpf.a
# $(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
# 	$(call msg,LIB,$@)
# 	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      		\
# 		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      	\
# 		INCLUDEDIR= LIBDIR= UAPIDIR=			      		\

$(OUTPUT)/vmlinux.h: $(wildcard vmlinux/*.h)
	ln -sf $(SRC)/lib/internal/ebpf/vmlinux/vmlinux-$(KERNEL_VERSION).h $(OUTPUT)/vmlinux.h

# Build BPF code
$(OUTPUT)/%.bpf.o: $(APPS_DIR)/%.bpf.c $(LIBBPF_OBJ) $(wildcard $(APPS_DIR)/%.h) $(OUTPUT)/vmlinux.h| $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: $(APPS_DIR)/%.c $(wildcard $(APPS_DIR)%.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@
	mv $@ $(TARGET_PATH)/$@
	echo $(APPS):$(DEPEND) >> $(OBJ_TOOLS_PATH)/$(SYSAK_RULES)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

