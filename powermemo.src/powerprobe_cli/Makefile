LIBPATH=
LIBS=
prog_name=pwrcli
prog_obj=pwrcli.o
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
clean:
	rm -f $(prog_name) *.o core 
