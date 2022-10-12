/*
    author: mkr
    date : 2022-10-12
    function: c”Ô—‘≤‚ ‘≤¢µ˜ ‘  
*/
#include <stdio.h>
#include "zmq.h"

 
int main(int argc, char *argv[])
{
	void *pctx = NULL;
	void *psock = NULL;
	const char *paddr = "tcp://*:9999";
 
	if ((pctx = zmq_ctx_new()) == NULL) {
		printf("create pctx error!\n");
		return 0;
	}
 
	if ((psock = zmq_socket(pctx, ZMQ_DEALER)) == NULL) {
		zmq_ctx_destroy(pctx);
		printf("create socket error!\n");
		return 0;
	}
 
	int irevtimeout = 5000;//millsecond
	if (zmq_setsockopt(psock, ZMQ_RCVTIMEO, &irevtimeout, sizeof(irevtimeout)) < 0) {
		zmq_close(psock);
		zmq_ctx_destroy(pctx);
		printf("setsockopt error!\n");
		return 0;
	}
 
	if (zmq_bind(psock, paddr) < 0) {
		zmq_close(psock);
		zmq_ctx_destroy(pctx);
		printf("zmq_bind error!\n");
		return 0;
	}
 
	printf("bind ok\n");
 
	while (1) {
		char msg[1024] = {0};
		errno = 0;
 
		if (zmq_recv(psock, msg, sizeof(msg), 0) < 0) {
			printf("errno = %s\n", zmq_strerror(errno));
			continue;
		}
		printf("recv msg: %s\n", msg);
	}
 
	return 0;
}