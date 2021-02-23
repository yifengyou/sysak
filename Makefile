KERNEL_VERSION ?= $(shell uname -r)
OUTPUT ?= $(shell pwd)/out
SRC := $(shell pwd)/source

OBJPATH := $(OUTPUT)/$(KERNEL_VERSION)
export KERNEL_VERSION
export SRC
export OBJPATH

.PHONY: target
ifneq ($(TARGET_PATH), )
target: $(OBJPATH)
	make -C $(TARGET_PATH)
endif

.PHONY: all
all: $(OBJPATH)
	make -C $(SRC)/lib
	make -C $(SRC)/tools

.PHONY: clean
clean:
	rm -rf $(OUTPUT)

$(OBJPATH):
	mkdir -p $(OBJPATH)
	mkdir -p $(OBJPATH)/tools
	mkdir -p $(OBJPATH)/lib
	cp $(SRC)/sysak $(OBJPATH)/

