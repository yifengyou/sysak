target: $(mods)

$(mods): %: %.sh
	cp $< $(OBJPATH)/tools/$@
