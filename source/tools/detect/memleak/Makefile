
target = memleak

mods := main.o slab.o page.o vmalloc.o

LDFLAGS += -lpthread
DEPEND := "prev{default modin};post{default modun}"
include $(SRC)/mk/csrc.mk
