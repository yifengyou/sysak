objs := $(foreach n, $(mods), $(OBJPATH)/$(n))

$(target): $(objs)
	gcc -o $(OBJ_TOOLS_PATH)/$@ $^ -L$(OBJ_LIB_PATH) $(EXTRA_LDFLAGS)

$(objs): $(mods)

$(mods): %.o : %.c
	gcc -I. $(EXTRA_CFLAGS) -c -o $(OBJPATH)/$@ $<
