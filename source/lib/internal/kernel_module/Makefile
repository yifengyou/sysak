KERNEL_BUILD_PATH := /usr/src/kernels/$(KERNEL_VERSION)

ifneq ($(KERNEL_BUILD_PATH), $(wildcard $(KERNEL_BUILD_PATH)))
KERNEL_BUILD_PATH := /lib/modules/$(KERNEL_VERSION)/build
endif

MODULE_SRC := $(SRC)/lib/internal/kernel_module

#common
sysak-objs += ./common/event.o ./common/hook.o ./common/stack.o entry.o sysak_mods.o

#modules
#sysak-objs += modules/test_module/test.o
sysak-objs += modules/signal/trace_sig.o

obj-m += sysak.o


EXTRA_CFLAGS := -I$(MODULE_SRC)

sysak_mod:
	make -C $(KERNEL_BUILD_PATH) M=$(MODULE_SRC)
	cp sysak.ko $(OBJ_LIB_PATH)/

clean:
	make -C $(KERNEL_BUILD_PATH) M=$(MODULE_SRC) clean
