#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void case1()
{
	printf("Test case 1\n");
}

void case2()
{
	printf("Test case 2\n");
}

void case3()
{
	printf("Test case 3\n");
}

void case4()
{
	printf("Test case 4\n");
}

int main()
{
	while (1)
	{
		case1();
		case2();
		sleep(1);
		case3();
		case4();	
	}
}
