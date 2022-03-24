target = hangdetect
ifneq ($(wildcard $(SRC)/lib/internal/kernel_module/modules/iosdiag/include/$(KERNEL_VERSION)),)
mods := main.o base_info.o json_format.o
KERNEL_DEPEND=Y

LDFLAGS += -lrt
include $(SRC)/mk/csrc.mk
else
all:
endif

