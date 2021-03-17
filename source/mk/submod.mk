$(target):
	make -C $(SUBMOD_SRC) $(MAKE_ARGS)
	cp $(target) $(OBJ_TOOLS_PATH)/
	echo $(target):$(DEPEND) >> $(OBJ_TOOLS_PATH)/$(SYSAK_RULES)

.PHONY: $(target)
