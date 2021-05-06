ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
SOURCE_PATH := $(KERNEL_VERSION)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
SOURCE_PATH := .
endif

exist := $(shell if [ -f $(SOURCE_PATH)/$(target) ]; then echo "exist"; else echo "notexist"; fi;)
ifeq ($(exist), exist)
$(target):
	cp $(SOURCE_PATH)/$(target) $(TARGET_PATH)/
	echo $(target):$(DEPEND) >> $(TARGET_PATH)/$(SYSAK_RULES)
else
$(target):
	@echo no kernel version
endif

.PHONY: $(target)
