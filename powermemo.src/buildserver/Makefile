LIBPATH=
LIBS=
prog_name=tcpsrv
prog_obj=tcpsrv.o
CC=gcc 
STRIP=strip 

all: $(prog_name)
$(prog_name): $(prog_obj)
	$(CC) -o $(prog_name) $(prog_obj) $(LIBPATH) $(LIBS)
	$(STRIP) -s $(prog_name)
.c.o: 
	$(CC) -c $< $(CFLAGS)

install:
	@echo -e "\033[32mInstalling tcp server ...\033[0m"
	cp -f /home/vincent/rowboat-android/kernel/vmlinux ./
	arm-eabi-objdump -d vmlinux > vmlinux.asm
	./util_funandaddr -a vmlinux.asm > vmlinux.fun

clean:
	rm -f $(prog_name) *.o core *.asm $(probe_app) vmlinux uprobe_test *.fun
