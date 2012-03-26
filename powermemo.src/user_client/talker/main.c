

#include <stdlib.h>
#include <stdio.h>

enum {
	PROCESS_REQUEST = 0,
	CLASS_REQUEST,
	METHOD_REQUEST
};

void response(int type, const char *filename);

int main(int argc, char* argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: ./talker request [options]\n");
		exit(EXIT_FAILURE);
	}

	int type = atoi(argv[1]);
	if ((type == CLASS_REQUEST || type == METHOD_REQUEST) && argc < 3) {
		fprintf(stderr, "Error: too few arguments\n");
		exit(EXIT_FAILURE);
	}

	const char *filename = (type == PROCESS_REQUEST ? NULL : argv[2]);

	if (filename != NULL) {
		fprintf(stderr, "file: [%s]\n", filename);
	}

	response(type, filename);


	exit(EXIT_SUCCESS);
}

void response(int type, const char *filename)
{
	if (filename != NULL && (type == CLASS_REQUEST || type == METHOD_REQUEST)) {
		FILE *fp = fopen(filename, "rb");
		
		if (fp == NULL) {
			fprintf(stderr, "Error: can't open file\n");
			exit(EXIT_FAILURE);
		}

		int ch;
		while ((ch = fgetc(fp)) != EOF) {
			putc(ch, stdout);
		}
	}

}


