target := pagescan

ARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
		-e s/arm.*/arm/ -e s/sa110/arm/ -e s/aarch64.*/arm/)
KMAJ := $(shell uname -r | awk -F "." '{print $$1}')
KMIN := $(shell uname -r | awk -F "." '{print $$2}')
KERNEL := $(shell echo KERNEL_$(KMAJ)_$(KMIN))

HEADERS = $(wildcard *.h)
HEADERS += $(wildcard kernel/*.h)
HEADERS += $(wildcard arch/$(ARCH)/*.h)

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
mods:= $(OBJECTS)

CFLAGS += -Iarch/$(ARCH)
CFLAGS += -Ikernel
CFLAGS += -D$(KERNEL)
include $(SRC)/mk/csrc.mk
