CC	:= agcc
INSTALL_PATH := ../../../powermemo.binary/user_client

talker: main.o
	$(CC) -o talker main.o -Wall

main.o: main.c
	$(CC) -c main.c -Wall

clean:
	rm -rf *.o talker

install:
	cp -rf talker $(INSTALL_PATH)

