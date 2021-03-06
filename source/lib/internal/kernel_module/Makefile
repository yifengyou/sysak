KERNEL_BUILD_PATH := /usr/src/kernels/$(KERNEL_VERSION)

ifneq ($(KERNEL_BUILD_PATH), $(wildcard $(KERNEL_BUILD_PATH)))
KERNEL_BUILD_PATH := /lib/modules/$(KERNEL_VERSION)/build
endif

MODULE_SRC := $(SRC)/lib/internal/kernel_module

#common
sysak-objs += ./common/chrdev.o  ./common/event.o ./common/hook.o ./common/stack.o ./common/proc.o
sysak-objs += ./common/blackbox.o
sysak-objs += ./entry.o sysak_mods.o

#modules
#sysak-objs += modules/test_module/test.o
ifneq ($(findstring tracesig,$(TARGET_LIST)),)
sysak-objs += modules/signal/trace_sig.o
endif
ifneq ($(findstring memleak,$(TARGET_LIST)),)
sysak-objs += modules/memleak/memleak.o
sysak-objs += modules/memleak/objects.o
sysak-objs += modules/memleak/hashlist.o
endif
ifneq ($(findstring runlatency,$(TARGET_LIST)),)
sysak-objs += modules/sched/noschedule.o modules/sched/trace_irqoff.o modules/sched/trace_runqlat.o
endif
ifneq ($(findstring taskctl,$(TARGET_LIST)),)
sysak-objs += modules/task_ctl/task_ctrl.o
endif
ifneq ($(findstring schedtrace,$(TARGET_LIST)),)
sysak-objs += modules/schedtrace/schedtrace.o
endif
ifneq ($(findstring mmaptrace,$(TARGET_LIST)),)
sysak-objs += modules/mmaptrace/mmaptrace.o
endif
ifneq ($(findstring iosdiag,$(TARGET_LIST)),)
ifneq ($(wildcard $(MODULE_SRC)/modules/iosdiag/include/$(KERNEL_VERSION)),)
sysak-objs += modules/iosdiag/iosdiag.o modules/iosdiag/rq_hang.o modules/iosdiag/virtio_blk.o modules/iosdiag/nvme.o modules/iosdiag/scsi.o
endif
endif

obj-m += sysak.o


EXTRA_CFLAGS := -I$(MODULE_SRC)
EXTRA_CFLAGS += -I$(MODULE_SRC)/include
EXTRA_CFLAGS += -I$(SRC)/lib/uapi/include
ifneq ($(findstring iosdiag,$(TARGET_LIST)),)
ifneq ($(wildcard $(MODULE_SRC)/modules/iosdiag/include/$(KERNEL_VERSION)),)
EXTRA_CFLAGS += -I$(MODULE_SRC)/modules/iosdiag -I$(MODULE_SRC)/modules/iosdiag/include/$(KERNEL_VERSION)
endif
endif

sysak_mod:
	make -C $(KERNEL_BUILD_PATH) M=$(MODULE_SRC)
	cp sysak.ko $(OBJ_LIB_PATH)/

clean:
	make -C $(KERNEL_BUILD_PATH) M=$(MODULE_SRC) clean
