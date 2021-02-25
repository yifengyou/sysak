target: $(mods)

$(mods): %: %.sh
	cp $< $(OBJ_TOOLS_PATH)/$@
