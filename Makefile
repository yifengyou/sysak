KERNEL_VERSION ?= $(shell uname -r)
OBJPATH ?= $(shell pwd)/out
SRC := $(shell pwd)/source

OBJ_LIB_PATH := $(OBJPATH)/.sysak_compoents/lib/$(KERNEL_VERSION)
OBJ_TOOLS_PATH := $(OBJPATH)/.sysak_compoents/tools/$(KERNEL_VERSION)
SYSAK_RULES := .sysak.rules

export KERNEL_VERSION
export SRC
export OBJPATH
export OBJ_LIB_PATH
export OBJ_TOOLS_PATH
export SYSAK_RULES

.PHONY: target
ifneq ($(TARGET_PATH), )
target: $(OBJPATH)
	make -C $(TARGET_PATH)
endif

.PHONY: all install
all: $(OBJ_LIB_PATH) $(OBJ_TOOLS_PATH)
	make -C $(SRC)/lib
	make -C $(SRC)/tools
	cp $(SRC)/sysak $(OBJPATH)/
	chmod +x $(OBJPATH)/sysak
	chmod +x $(OBJPATH)/.sysak_compoents/tools/* -R

.PHONY: clean clean_middle
clean:
	make -C $(SRC)/lib clean
	rm -rf $(OBJPATH)
clean_middle:
	make -C $(SRC)/lib clean
	rm -rf $(OBJPATH)/*.o

$(OBJ_LIB_PATH):
	mkdir -p $(OBJ_LIB_PATH)
$(OBJ_TOOLS_PATH):
	mkdir -p $(OBJ_TOOLS_PATH)

install:
	cp $(OBJPATH)/sysak /usr/local/sbin/
	cp $(OBJPATH)/.sysak_compoents /usr/local/sbin/ -rf
