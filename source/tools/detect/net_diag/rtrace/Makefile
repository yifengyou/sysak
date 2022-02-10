ifndef KERNEL_VERSION
KERNEL_VERSION = $(shell uname -r)
SRC := /work/gitee/sysak/source
OBJPATH = /work/gitee/sysak/out
OBJ_LIB_PATH := $(OBJPATH)/.sysak_compoents/lib/$(KERNEL_VERSION)
OBJ_TOOLS_ROOT := $(OBJPATH)/.sysak_compoents/tools
OBJ_TOOLS_PATH := $(OBJPATH)/.sysak_compoents/tools/$(KERNEL_VERSION)
SYSAK_RULES := .sysak.rules

export SRC
export OBJPATH
export OBJ_LIB_PATH
export OBJ_TOOLS_ROOT
export OBJ_TOOLS_PATH
endif

TARGET_PATH := $(OBJ_TOOLS_ROOT)

.PHONY: rtrace

rtrace: lib bin

lib:
	make -C ebpf

bin:
	cd rtrace-delay && cargo build --release
	cd rtrace-drop && cargo build --release

	@echo "rtrace-delay" >> $(TARGET_PATH)/$(SYSAK_RULES)
	@echo "rtrace-drop" >> $(TARGET_PATH)/$(SYSAK_RULES)
	@echo "rtrace-basic" >> $(TARGET_PATH)/$(SYSAK_RULES)

target := rtrace
