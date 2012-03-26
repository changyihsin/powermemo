
KMNAME		:= powermemo
KERNEL_DIR	:= /home/$(USER)/rowboat-android/kernel

obj-m		:= $(KMNAME).o


all:
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules


clean:
	rm -rf modules.order Module.symvers $(KMNAME).mod.c *.ko *.o .*cmd .tmp_versions

