
#ifndef _DECODE_H_
#define _DECODE_H_

#include <stdio.h>
#include <stdlib.h>

int32_t decode_pu (unsigned char *pbuf, FILE *fd);
int32_t decode_mk (unsigned char *pbuf, FILE *fd);
int32_t decode_xmit (unsigned char *pbuf, FILE *fd);
int32_t decode_rcv (unsigned char *pbuf, FILE *fd);


#endif

