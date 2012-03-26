CC	:= agcc
INSTALL_PATH := ../../../powermemo.binary/user_client
CFLAGS += -DRECORD_COMM=1

memo: memo.o decode.o
	$(CC) $(CFLAGS) -o memo memo.o decode.o -Wall

memo.o: memo.c
	$(CC) $(CFLAGS) -c memo.c -Wall

decode.o: decode.c
	$(CC) $(CFLAGS) -c decode.c -Wall
	

clean:
	rm -rf *.o memo

install:
	cp -rf memo $(INSTALL_PATH)
