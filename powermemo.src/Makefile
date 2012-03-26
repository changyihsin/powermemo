KPATH:=./kernel_module
UPATH:=./user_client
all:
	make -C $(KPATH)
	make -C $(UPATH)
	make -C benchmark
	make -C powerprobe_cli
clean:
	make -C $(KPATH) clean
	make -C $(UPATH) clean
	make -C benchmark clean
	make -C powerprobe_cli clean

install:
	make -C $(KPATH) install
	make -C $(UPATH) install
	make -C benchmark install
	make -C powerprobe_cli install
	cp pm.sh ../powermemo.binary/user_client/
	cp rs.sh ../powermemo.binary/user_client/
	
