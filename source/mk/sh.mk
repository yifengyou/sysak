target: $(mods)

$(mods): %: %.sh
	cp $< $(OBJ_TOOLS_PATH)/$@
	echo $(target):$(DEPEND) >> $(OBJ_TOOLS_PATH)/$(SYSAK_RULES)
