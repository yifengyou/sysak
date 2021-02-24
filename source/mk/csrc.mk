objs := $(foreach n, $(mods), $(OBJPATH)/$(n))

$(target): $(objs)
	gcc -o $(OBJPATH)/tools/$@ $^ -L$(OBJPATH)/lib $(LDFLAGS)

$(objs): $(mods)

$(mods): %.o : %.c
	gcc -I. -c -o $(OBJPATH)/$@ $<
