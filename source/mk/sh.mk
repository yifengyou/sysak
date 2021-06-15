ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
endif

.PHONY: $(mods)

$(target): $(mods)
	cp $@.sh $(TARGET_PATH)/$@
	echo $(target):$(DEPEND) >> $(TARGET_PATH)/$(SYSAK_RULES)

$(mods):
	cp $@ $(TARGET_PATH)/ -rf
