all:
	make -C powermemo
	make -C powerprobe
	make -C probe_samples

clean:
	make -C powermemo clean
	make -C powerprobe clean
	make -C probe_samples clean
	rm -f modules.order Module.symvers

install:
	make -C powermemo install
	make -C powerprobe install
	make -C probe_samples install
