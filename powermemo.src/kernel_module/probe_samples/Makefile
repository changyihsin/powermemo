KERNELDIR:=../../../../kernel
BIN_USER := uprobes.ko
BIN_KERNEL := kprobes.ko
BIN_JPROBE := jprobe.ko
BIN_URETPROBE := uretprobe.ko
BIN_KRETPROBE := kretprobe.ko
obj-m += kprobes.o uprobes.o uretprobe.o kretprobe.o
TARGET := ../../../powermemo.binary/kernel_module

all:
	@echo -e "\033[32mBuilding dynamic probe  module...\033[0m"
	$(Q)make -C $(KERNELDIR) ARCH=arm CROSS_COMPILE=arm-eabi- M=`pwd` modules

clean:
	@echo -e "\033[32mCleaning dynamic probe  module...\033[0m"
	$(Q)make -C $(KERNELDIR) ARCH=arm CROSS_COMPILE=arm-eabi- M=`pwd` clean
	$(Q)rm -f *~ Module.symvers *.nccout modules.order

install:
	@echo -e "\033[32mInstalling dynamic probe  module...\033[0m"
	$(Q)sudo cp -a ./$(BIN_USER) $(TARGET)
	$(Q)sudo cp -a ./$(BIN_KERNEL) $(TARGET)
	$(Q)sudo cp -a ./$(BIN_KRETPROBE) $(TARGET)
	$(Q)sudo cp -a ./$(BIN_URETPROBE) $(TARGET)

