$(target):
	make -C $(SUBMOD_SRC) $(MAKE_ARGS)
	cp $(target) $(OBJ_TOOLS_PATH)/

.PHONY: $(target)
