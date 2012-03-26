CC:=agcc
TARGET:=../../../powermemo.binary/user_client


all:
	$(CC) -Wall -o poweragent poweragent.c -I../../kernel_module/powerprobe
install:
	sudo cp poweragent $(TARGET)
clean:
	rm -rf poweragent 
