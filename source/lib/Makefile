.PHONY: all clean

all:
ifeq ($(BUILD_KERNEL_MODULE), YES)
	make -C internal/kernel_module
endif
	make -C uapi
ifeq ($(BUILD_LIBBPF), YES)
	make -C internal/ebpf/libbpf/src BUILD_STATIC_ONLY=1 	\
		OBJDIR=$(OBJ_LIB_PATH)/libbpf DESTDIR=$(OBJ_LIB_PATH) 		\
		INCLUDEDIR= LIBDIR= UAPIDIR=						\
		install
endif

clean:
ifeq ($(BUILD_KERNEL_MODULE), YES)
	make -C internal/kernel_module clean
endif
	make -C internal/ebpf/libbpf/src clean

