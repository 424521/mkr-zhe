/*
    author: mkr
    date: 2022-10-12
    function: ≤‚ ‘zeromqc”Ô—‘≤ø∑÷
*/
#include <stdio.h>
#include "zmq.h"
 
 
int main(int argc, char *argv[])
{
	void *pctx = NULL;
	void *psock = NULL;
 
	const char *paddr = "tcp://127.0.0.1:9999";
 
	if ((pctx = zmq_ctx_new()) == NULL) {
		printf("zmq_ctx_new error\n");
		return 0;
	}
 
	if ((psock = zmq_socket(pctx, ZMQ_DEALER)) == NULL){
		zmq_ctx_destroy(pctx);
		printf("zmq_socket error\n");
		return 0;
	}
 
	int isendtimeout = 5000;//millsecond
 
	if (zmq_setsockopt(psock, ZMQ_RCVTIMEO, &isendtimeout, sizeof(isendtimeout)) < 0) {
		printf("zmq_setsockopt error\n");
		zmq_close(psock);
		zmq_ctx_destroy(pctx);
		return 0;
	}
 
	if (zmq_connect(psock, paddr) < 0) {
		printf("zmq_connect error\n");
		zmq_close(psock);
		zmq_ctx_destroy(pctx);
		return 0;
	}
 
	while(1) {
		static int i = 0;
		char msg[1024] = {0};
 
		snprintf(msg, sizeof(msg), "hello world: %3d", i++);
		printf("enter to send\n");
		if (zmq_send(psock, msg, sizeof(msg), 0) < 0) {
			printf("zmq_send error\n");
			continue;
		}
		printf("zmq_send ok: %s\n", msg);
		getchar();
	}
 
	return 0;
}