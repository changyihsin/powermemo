Q=
CC=gcc
CFLAGS=
STRIP=strip

APPLET:=line2addrver2

all: $(APPLET)

$(APPLET): line2addrver2.c 
	@echo -e "\033[32mBuilding line2addr tools ... \033[0m"
	$(Q)$(CC) $(CFLAGS) -o $@ $@.c
	$(Q)$(STRIP) --remove-section=.note --remove-section=.comment $@

install:
	@echo -e "\033[32mInstalling line2addr tools ... \033[0m"

clean:
	@echo -e "\033[32mCleaning line2addr tools ... \033[0m"
	$(Q)rm -f $(APPLET) *.o

.PHONY: all install clean

