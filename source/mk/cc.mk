objs := $(foreach n, $(mods), $(OBJPATH)/$(n)) 

$(target): $(objs)
	g++ -o $(OBJ_TOOLS_PATH)/$@ $^ -L$(OBJ_LIB_PATH) $(EXTRA_LDFLAGS)

$(objs): $(mods)

$(mods): %.o : %.cpp
	g++ -I. $(EXTRA_CFLAGS) -c -o $(OBJPATH)/$@ $<
