KERNEL_BUILD_PATH := /usr/src/kernels/$(KERNEL_VERSION)/
MODULE_SRC := $(SRC)/lib/internal/kernel_module

#common
sysak-objs += ./common/event.o ./common/hook.o ./common/stack.o entry.o sysak_mods.o

#modules
sysak-objs += modules/test_module/test.o

obj-m += sysak.o


EXTRA_CFLAGS := -I$(MODULE_SRC)

sysak_mod:
	make -C $(KERNEL_BUILD_PATH) M=$(MODULE_SRC)
	cp sysak.ko $(OBJPATH)/lib

clean:
	make -C $(KERNEL_BUILD_PATH) M=$(MODULE_SRC) clean
