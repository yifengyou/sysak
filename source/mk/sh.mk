ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
endif

target: $(mods)

$(mods): %: %.sh
	cp $< $(TARGET_PATH)/$@
	echo $(target):$(DEPEND) >> $(TARGET_PATH)/$(SYSAK_RULES)
