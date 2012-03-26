#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

typedef unsigned long long uint64;

uint64
now(void)
{
	struct timeval t;
	uint64	m;

	(void) gettimeofday(&t, (struct timezone *) 0);
	m = t.tv_sec;
	m *= 1000000;
	m += t.tv_usec;
	return (m);
}

int 
main(int argc, char **argv)
{
	uint64 start = 0; 
	uint64 end = 0;
	unsigned long i;  
	
	if (argc < 2) {
		printf("usage:\n");
		return 0;
	}
	for(i = 0; i < 655350; i++)
	{
		printf("i=%d\n");
		now();	
	}
	return 0;
}
