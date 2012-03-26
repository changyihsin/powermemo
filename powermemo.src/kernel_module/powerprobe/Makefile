KERNELDIR := ../../../../kernel
BIN_KERNEL := power.ko
INSTALL_PATH := ../../../powermemo.binary/kernel_module
obj-m += power.o


all:
	@echo -e "\033[32mBuilding powerprobe kernel module...\033[0m"
	$(Q)make -C $(KERNELDIR) ARCH=arm CROSS_COMPILE=arm-eabi- M=`pwd` modules

clean:
	@echo -e "\033[32mCleaning powerprobe kernel module...\033[0m"
	$(Q)make -C $(KERNELDIR) ARCH=arm CROSS_COMPILE=arm-eabi- M=`pwd` clean
	$(Q)rm -f *~ Module.symvers modules.order

install:
	@echo -e "\033[32mInstalling powerprobe kernel module...\033[0m"
	sudo cp $(BIN_KERNEL) $(INSTALL_PATH)

.PHONY: all install clean

