objs := $(foreach n, $(mods), $(OBJPATH)/$(n)) 

CFLAGS += $(EXTRA_CFLAGS) -I$(SRC)/lib/uapi/include
LDFLAGS += $(EXTRA_LDFLAGS)

ifeq ($(KERNEL_DEPEND), Y)
TARGET_PATH := $(OBJ_TOOLS_PATH)
else
TARGET_PATH := $(OBJ_TOOLS_ROOT)
endif

$(target): $(objs)
	g++ -o $(TARGET_PATH)/$@ $^ -L$(OBJ_LIB_PATH) $(LDFLAGS) --static
	echo $(target):$(DEPEND) >> $(OBJ_TOOLS_PATH)/$(SYSAK_RULES)

$(objs): $(mods)

$(mods): %.o : %.cpp
	g++ -I. $(CFLAGS) -c -o $(OBJPATH)/$@ $<
