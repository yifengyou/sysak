objs := $(foreach n, $(mods), $(OBJPATH)/$(n)) 

$(target): $(objs)
	g++ -o $(OBJ_TOOLS_PATH)/$@ $^ -L$(OBJ_LIB_PATH) $(LDFLAGS)

$(objs): $(mods)

$(mods): %.o : %.cpp
	g++ -I. -c -o $(OBJPATH)/$@ $<
