PWD:=$(shell pwd)
SRC_DIR:=./
OBJ_DIR:=.
CC:=agcc
TARGET:= 


PROG_NAME = uprobe_test

PROGS_SRC = ./uprobe_test.c

OBJ_NAMES=$(PROGS_SRC:%.c=%.o)

all: echo_msg $(PROG_NAME) objdump fun2addr

$(PROG_NAME):$(OBJ_NAMES)
	$(CC) -g -o $@ $(OBJ_NAMES)

$(OBJ_NAMES):%.o:%.c
	$(CC) -g -c $< -o $(OBJ_DIR)/$@

echo_msg:
	@echo -e "\033[32mCompile $(PROG_NAME) ...\033[0m"

install:
	@echo -e "\033[32mInstalling uprobe_test ...\033[0m"
	cp $(PROG_NAME) ../../powermemo.binary/user_client

clean:
	@echo -e "\033[32mClean ${PROG_NAME}...\033[0m"
	sudo rm -rf $(OBJ_DIR)/*.o $(PROG_NAME) $(PROG_NAME).asm $(PROG_NAME).fun

objdump:
	arm-eabi-objdump -d $(PROG_NAME) > $(PROG_NAME).asm

fun2addr:
	./util_funandaddr -a $(PROG_NAME).asm > $(PROG_NAME).fun

.PHONY: all echo_msg install clean objdump fun2addr

