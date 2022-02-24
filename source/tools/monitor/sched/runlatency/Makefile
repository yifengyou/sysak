target := runlatency
DEPEND := "prev{-e modin};post{-d modun}"
mods := runlatency.o json_dump.o parser.o
EXTRA_CFLAGS += -I ./include
EXTRA_LDFLAGS += -lsysak

include $(SRC)/mk/csrc.mk
