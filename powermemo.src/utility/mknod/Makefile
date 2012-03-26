
CC	:= agcc

mknod: mknod.o
	$(CC) -o mknod mknod.o -Wall

mknod.o: mknod.c
	$(CC) -c mknod.c -Wall


clean:
	rm -rf *.o mknod

