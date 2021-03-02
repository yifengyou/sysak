KERNEL_VERSION ?= $(shell uname -r)
OBJPATH ?= $(shell pwd)/out
SRC := $(shell pwd)/source

OBJ_LIB_PATH := $(OBJPATH)/sysak/lib/$(KERNEL_VERSION)
OBJ_TOOLS_PATH := $(OBJPATH)/sysak/tools/$(KERNEL_VERSION)

export KERNEL_VERSION
export SRC
export OBJPATH
export OBJ_LIB_PATH
export OBJ_TOOLS_PATH

.PHONY: target
ifneq ($(TARGET_PATH), )
target: $(OBJPATH)
	make -C $(TARGET_PATH)
endif

.PHONY: all install
all: $(OBJPATH)/bin $(OBJ_LIB_PATH) $(OBJ_TOOLS_PATH)
	make -C $(SRC)/lib
	make -C $(SRC)/tools
	cp $(SRC)/sysak $(OBJPATH)/bin/
	chmod +x $(OBJPATH)/bin/*
	chmod +x $(OBJPATH)/sysak/tools/* -R

.PHONY: clean clean_middle
clean:
	make -C $(SRC)/lib clean
	rm -rf $(OBJPATH)
clean_middle:
	make -C $(SRC)/lib clean
	rm -rf $(OBJPATH)/*.o

$(OBJPATH)/bin:
	mkdir -p $(OBJPATH)/bin
$(OBJ_LIB_PATH):
	mkdir -p $(OBJ_LIB_PATH)
$(OBJ_TOOLS_PATH):
	mkdir -p $(OBJ_TOOLS_PATH)

install:
	cp $(OBJPATH)/bin/sysak /usr/local/sbin/
	cp $(OBJPATH)/sysak /usr/local/ -rf
