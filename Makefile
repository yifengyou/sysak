ifneq ($(wildcard config-host.mak),)
include config-host.mak
else
config-host.mak:
	@echo "Please call configure before running make!"
	@exit 1
endif

SRC := $(shell pwd)/source

OBJ_LIB_PATH := $(OBJPATH)/.sysak_compoents/lib/$(KERNEL_VERSION)
OBJ_TOOLS_ROOT := $(OBJPATH)/.sysak_compoents/tools
OBJ_TOOLS_PATH := $(OBJPATH)/.sysak_compoents/tools/$(KERNEL_VERSION)
SYSAK_RULES := .sysak.rules

export KERNEL_VERSION
export SRC
export OBJPATH
export OBJ_LIB_PATH
export OBJ_TOOLS_ROOT
export OBJ_TOOLS_PATH
export SYSAK_RULES
export BUILD_KERNEL_MODULE
export BUILD_LIBBPF

export EXTRA_LDFLAGS
export TARGET_LIST

.PHONY: all lib tools binary install $(TARGET_LIST)
all: config-host.mak $(OBJ_LIB_PATH) $(OBJ_TOOLS_PATH) lib tools binary

lib:
	make -C $(SRC)/lib

tools: $(TARGET_LIST)
$(TARGET_LIST):
	make -C $@ -j

binary:
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
