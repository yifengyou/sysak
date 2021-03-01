objs := $(foreach n, $(mods), $(OBJPATH)/$(n)) 

CFLAGS += $(EXTRA_CFLAGS) -I$(SRC)/lib/uapi/include
LDFLAGS += $(EXTRA_LDFLAGS)


$(target): $(objs)
	g++ -o $(OBJ_TOOLS_PATH)/$@ $^ -L$(OBJ_LIB_PATH) $(LDFLAGS) --static

$(objs): $(mods)

$(mods): %.o : %.cpp
	g++ -I. $(CFLAGS) -c -o $(OBJPATH)/$@ $<
