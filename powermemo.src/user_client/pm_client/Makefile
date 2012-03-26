CC	:= agcc
INSTALL_PATH := ../../../powermemo.binary/user_client

pm_client: main.o protocol_util.o client.o runscript.o
	$(CC) -o pm_client main.o protocol_util.o client.o runscript.o -Wall


main.o: main.c
	$(CC) -c main.c -Wall

protocol_util.o: protocol_util.c
	$(CC) -c protocol_util.c -Wall

client.o: client.c
	$(CC) -c client.c -Wall

runscript.o: runscript.c
	$(CC) -c runscript.c -Wall

clean:
	rm -rf *.o pm_client

install:
	cp -rf pm_client $(INSTALL_PATH)
