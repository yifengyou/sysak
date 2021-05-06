.PHONY: sysaklib clean

all:
	make -C internal/kernel_module
	make -C uapi
	make -C internal/ebpf/libbpf/src BUILD_STATIC_ONLY=1 	\
		OBJDIR=$(OBJ_LIB_PATH)/libbpf DESTDIR=$(OBJ_LIB_PATH) 		\
		INCLUDEDIR= LIBDIR= UAPIDIR=						\
		install
clean:
	make -C internal/kernel_module clean
	make -C internal/ebpf/libbpf/src clean

