
CC	:= agcc


pmemo_client: pmemo_client.o RS232_trigger.o my_iw_get_stats.o
	$(CC) -o pmemo_client pmemo_client.o RS232_trigger.o my_iw_get_stats.o -Wall

pmemo_client.o: pmemo_client.c
	$(CC) -c pmemo_client.c -Wall

RS232_trigger.o: RS232_trigger.c
	$(CC) -c RS232_trigger.c -Wall

my_iw_get_stats.o: my_iw_get_stats.c
	$(CC) -c my_iw_get_stats.c

clean:
	rm -rf pmemo_client *.o



