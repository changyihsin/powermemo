
KMNAME		:= powermemo
KERNEL_DIR	:= ../../../../kernel
INSTALL_PATH := ../../../powermemo.binary/kernel_module

obj-m		:= $(KMNAME).o

all:
	make -C $(KERNEL_DIR) ARCH=arm CROSS_COMPILE=arm-eabi- M=`pwd` modules


clean:
	rm -rf modules.order Module.symvers $(KMNAME).mod.c *.ko *.o .*cmd .tmp_versions

install:
	sudo cp -f *.ko $(INSTALL_PATH)
