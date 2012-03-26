
#include <unistd.h>
#include "powermemo_data.h"
#include "decode.h"

	
int32_t decode_pu (unsigned char *pbuf, FILE *fd)
{
	struct processor_u *pu;
	int32_t i;
	int32_t nr_p_u = *(int32_t *)pbuf;

	printf("decode_pu\n");

	for(i=0; i<nr_p_u; i++){
		pu = (struct processor_u *)(pbuf + 8 + i * sizeof(struct processor_u));
#ifdef RECORD_COMM
		fprintf(fd,"%d,%s,%ld,%ld\n",pu->pid, pu->comm, pu->t_entry, pu->t_exit);
#else
		fprintf(fd,"%d,#,%ld,%ld\n",pu->pid, pu->t_entry, pu->t_exit);
#endif
	}

	sync(); //sync() doesn't block

	return 8 + nr_p_u * sizeof(struct processor_u);
}


int32_t decode_mk (unsigned char *pbuf, FILE *fd)
{
	struct markerfunc_u *mk;
	int32_t i;
	int32_t nr_markerfunc_u = *(int32_t *)pbuf;

	printf("decode_mk\n");

	for(i=0; i<nr_markerfunc_u; i++){
		mk = (struct markerfunc_u *)(pbuf + 8 + i * sizeof(struct markerfunc_u));
		fprintf(fd,"%d,%d,%ld,%ld,%s\n",mk->pid, mk->fid, mk->t_entry, mk->t_exit,mk->funname);
	}

	sync(); //sync() doesn't block

	return 8 + nr_markerfunc_u * sizeof(struct markerfunc_u);
}


int32_t decode_xmit (unsigned char *pbuf, FILE *fd)
{
	struct xmit_u *xmit;
	int32_t i;
	int32_t nr_xmit_u = *(int *)pbuf;

	printf("decode_xmit\n");
	for(i=0; i<nr_xmit_u; i++){
		xmit = (struct xmit_u *)(pbuf + 8 + i * sizeof(struct xmit_u));
		fprintf(fd,"%d,%d,%ld,%ld\n",xmit->pid, xmit->tx_bitrate,xmit->packet_size,xmit->t_departure);
	}

	sync(); //sync() doesn't block

	return 8 + nr_xmit_u * sizeof(struct xmit_u);
}

int32_t decode_rcv (unsigned char *pbuf, FILE *fd)
{
	struct rcv_u *rcv;
	int32_t i;
	int32_t nr_rcv_u = *(int *)pbuf;

	printf("decode_rcv\n");
	for(i=0; i<nr_rcv_u; i++){
		rcv = (struct rcv_u *)(pbuf + 8 + i * sizeof(struct rcv_u));
		fprintf(fd,"%d,%d,%ld,%ld\n",rcv->pid, rcv->rx_bitrate, rcv->packet_size, rcv->t_arrival);
	}

	sync(); //sync() doesn't block

	return 8 + nr_rcv_u * sizeof(struct rcv_u);
}



