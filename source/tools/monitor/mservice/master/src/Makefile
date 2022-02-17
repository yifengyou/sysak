CC = gcc
SRC = tsar.c config.c debug.c framework.c output_file.c output_print.c output_db.c output_tcp.c output_nagios.c httpserver.c common.c
OBJ = $(patsubst %.c, %.o,$(SRC))

BIN = mservice

ODIR = obj

CFLAGS = -MD -g -O2 -Wall -I../include -I$(ODIR)/include
LDFLAGS += -lm -ldl -rdynamic -lpthread

all: $(BIN)

$(BIN): $(OBJ)
	@echo LINK $(BIN)
	$(CC) $^ -o $(BIN) -I$(INCLUDE_DIR) $(CFLAGS) $(LDFLAGS)

$(OBJ): $(ODIR)

$(ODIR)/%.o : %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -c -o $@ $<

$(ODIR):
	@mkdir -p $@

clean:
	rm -rf *.o *.d $(BIN) $(ODIR);

OBJS = *.o
-include $(OBJS:.o=.d)
