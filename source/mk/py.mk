ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
endif

target: $(mods)

$(mods): %: %.py
	cp $< $(TARGET_PATH)/$@
	echo $(target):$(DEPEND) >> $(OBJ_TOOLS_PATH)/$(SYSAK_RULES)
