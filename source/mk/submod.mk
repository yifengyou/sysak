ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
endif

$(target):
	make -C $(SUBMOD_SRC) $(MAKE_ARGS) INSTALL_PRE=$(TARGET_PATH) install
	echo $(target):$(DEPEND) >> $(OBJ_TOOLS_PATH)/$(SYSAK_RULES)

.PHONY: $(target)
