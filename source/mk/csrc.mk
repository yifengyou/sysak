objs := $(foreach n, $(mods), $(OBJPATH)/$(n))

CFLAGS += $(EXTRA_CFLAGS) -I$(SRC)/lib/uapi/include
LDFLAGS += $(EXTRA_LDFLAGS)

$(target): $(objs)
	gcc -o $(OBJ_TOOLS_PATH)/$@ $^ -L$(OBJ_LIB_PATH) $(LDFLAGS) --static

$(objs): $(mods)

$(mods): %.o : %.c
	gcc -I. $(CFLAGS) -c -o $(OBJPATH)/$@ $<
