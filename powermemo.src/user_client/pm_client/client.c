
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/uio.h>

#include <unistd.h>
#include <netdb.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "client.h"


static void setUp_activeSockaddr(struct sockaddr_in *sin,struct hostent *host,int port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr = *((struct in_addr *)host->h_addr);
	sin->sin_port = htons(port);
}

int activeSocket(char *host_name, int port)
{
	struct sockaddr_in dest;
	struct hostent *host;
	int sockfd;

	if((host = gethostbyname(host_name)) < 0) {
		perror("gethostbyname");
		exit(EXIT_FAILURE);
	}

	setUp_activeSockaddr(&dest,host ,port);

	if((sockfd = socket(PF_INET, SOCK_STREAM, 0) )< 0){
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}



