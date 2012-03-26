#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../test_area/module_test/benchmark.h"


#define DEVNAME "/dev/benchmark"

void nopinst()
{
	asm(
		".rept 800000"
		"nop\n"
		".endr"
		);
}
void nopinst_20000()
{
	asm(
		".rept 20000"
		"nop\n"
		".endr"
		);
}
void nopinst_40000()
{
	asm(
		".rept 40000"
		"nop\n"
		".endr"
		);
}
void nopinst_80000()
{
	asm(
		".rept 80000"
		"nop\n"
		".endr"
		);
}
void nopinst_160000()
{
	asm(
		".rept 160000"
		"nop\n"
		".endr"
		);
}

void nopinst_1000000()
{
	int i = 0;

	for (i = 0; i < 10000; i++)
	{
		asm(
			".rept 10000"
			"nop\n"
			".endr"
		);
	}
}

void nopinst_EnableLED()
{
	asm(
		".rept 10000"
		"nop\n"
		".endr"
		);
}
void nopinst_20000_EnableLED()
{
	asm(
		".rept 20000"
		"nop\n"
		".endr"
		);
}
void nopinst_40000_EnableLED()
{
	asm(
		".rept 40000"
		"nop\n"
		".endr"
		);
}
void nopinst_80000_EnableLED()
{
	asm(
		".rept 80000"
		"nop\n"
		".endr"
		);
}
void nopinst_160000_EnableLED()
{
	asm(
		".rept 160000"
		"nop\n"
		".endr"
		);
}



void nopinst_pre()
{
	asm(
		".rept 10000"
		"nop\n"
		".endr"
		);
}

void mvnsinst()
{
	asm(
		".rept 10000"
		"mvns r1, r1\n"
		".endr"
		);
}

void eorinst() 
{
	asm(
		".rept 10000"
		"eor r1, r1, #3\n"
		".endr"
		);
}

void orrinst() 
{
	asm(
		".rept 10000"
		"orr r1, r1, #3\n"
		".endr"
		);
}

void mulplyinst()
{
	asm(
		".rept 800000"
		"mul r10,r10,r11\n"
		".endr"
		);
}
void mulplyinst_20000()
{
	asm(
		".rept 20000"
		"mul r1,r2,r3\n"
		".endr"
		);
}
void mulplyinst_40000()
{
	asm(
		".rept 40000"
		"mul r1,r2,r3\n"
		".endr"
		);
}
void mulplyinst_80000()
{
	asm(
		".rept 80000"
		"mul r1,r2,r3\n"
		".endr"
		);
}
void mulplyinst_160000()
{
	asm(
		".rept 160000"
		"mul r1,r2,r3\n"
		".endr"
		);
}
void mulplyinst_1000000()
{
	int i = 0;

	for (i = 0; i < 10000; i++)
	{
		asm(
			".rept 10000"
			"ldr r0, =0x8500\n"
			".endr"
		);
	}
}

void addinst()
{
	asm(
		".rept 800000"
		"add r1,r2,r3\n"
		".endr"
		);
}
void addinst_20000()
{
	asm(
		".rept 20000"
		"add r1,r2,r3\n"
		".endr"
		);
}
void addinst_40000()
{
	asm(
		".rept 40000"
		"add r1,r2,r3\n"
		".endr"
		);
}
void addinst_80000()
{
	asm(
		".rept 80000"
		"add r1,r2,r3\n"
		".endr"
		);
}

void addinst_160000()
{
	asm(
		".rept 160000"
		"add r1,r2,r3\n"
		".endr"
		);
}

void addinst_500000()
{
	asm(
		".rept 500000"
		"add r1,r2,r3\n"
		".endr"
		);
}

void addmulplyinst()
{
	asm(
		".rept 5000"
		"mul r1,r2,r3\n"
		"add r1,r2,r3\n"
		".endr"
		);
}

void subinst()
{
	asm(
		".rept 10000"
		"sub r1, r2, r3\n"
		".endr"
		);
}
void subinst_20000()
{
	asm(
		".rept 20000"
		"sub r1, r2, r3\n"
		".endr"
		);
}
void subinst_40000()
{
	asm(
		".rept 40000"
		"sub r1, r2, r3\n"
		".endr"
		);
}
void subinst_80000()
{
	asm(
		".rept 80000"
		"sub r1, r2, r3\n"
		".endr"
		);
}
void subinst_160000()
{
	asm(
		".rept 160000"
		"sub r1, r2, r3\n"
		".endr"
		);
}


void rsbinst()
{
	asm(
		".rept 10000"
		"rsb r1, r2, r3\n"
		".endr"
		);
}

void ldrinst()
{
	asm(
		".rept 800000"
		"ldr r10, =0x8900\n"
		".endr"
		);
}
void ldminst()
{
	asm(
		".rept 800000"
		"ldm r1, {r2}\n"
		".endr"
		);
}
#if 0
void strinst()
{
	asm(
		".rept 10000"
		"str r1, =0x8500\n"
		".endr"
		);
}
#endif

void mulply()
{
	unsigned long i, a, b, c;

	a = 1;
	b = 2;
	c = 3;
	for (i = 0; i < 5000000; i++)
	{
		a += b*c;
	}
}
void add()
{
	unsigned long i, a, b, c;

	a = 1;
	b = 2;
	c = 3;
	for (i = 0; i < 5000000; i++)
		a += b + c;
	
}
int global_fd;

int main(int argc, char *argv[])
{
	#if 0
	struct benchmark data;
	global_fd = open(DEVNAME, O_RDWR);
	nopinst();
	nopinst_20000();
	nopinst_40000();
	nopinst_80000();
	nopinst_160000();
	ioctl(global_fd, ENABLE_LED_CMD, &data);
	sleep(5);
	nopinst_EnableLED();
	nopinst_20000_EnableLED();
	nopinst_40000_EnableLED();
	nopinst_80000_EnableLED();
	nopinst_160000_EnableLED();
	ioctl(global_fd, DISABLE_LED_CMD, &data);
	close(global_fd);	
	mulplyinst();
	mulplyinst_20000();
	mulplyinst_40000();	
	mulplyinst_80000();
	mulplyinst_160000();
	addinst();
	addinst_20000();
	addinst_40000();
	addinst_80000();
	addinst_160000();
	subinst();
	subinst_20000();
	subinst_40000();
	subinst_80000();
	subinst_160000();
	#endif
	
	
	ldrinst();	
	nopinst();
	ldminst();	
	addinst();
	mulplyinst();
	
	//mulply();	
	//add();
}
