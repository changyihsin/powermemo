
#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_


/* prefix for all the protocol packets*/
struct pm_prefix {

	char sig;
	unsigned char type;
};


struct rs_packet_prefix {
	unsigned char start_time[4];
	unsigned char end_time[4];
	unsigned char cmd_length;
};

enum {
	PROCESS_REQUEST = 0,
	CLASS_REQUEST,
	METHOD_REQUEST,
	END_SECTION,
	RUN_SCRIPT
};




#endif

