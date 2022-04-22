target := btf

SRC_VMLINUX := vmlinux-btf/vmlinux-$(KERNEL_VERSION)

ifeq ($(SRC_VMLINUX), $(wildcard $(SRC_VMLINUX)))
$(target):
	cp btf.sh $(OBJ_TOOLS_ROOT)/btf
	cp $(SRC_VMLINUX) $(OBJ_TOOLS_PATH)/
	cp pahole $(OBJ_TOOLS_ROOT)/pahole
else
$(target):
	cp btf.sh $(OBJ_TOOLS_ROOT)/btf
	cp pahole $(OBJ_TOOLS_ROOT)/pahole
endif
