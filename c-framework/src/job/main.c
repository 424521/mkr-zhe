/*
    author: mkr
    date: 2022-10-13
    function: ���������д����̣߳����ڽ�����Ϣ��������Ϣ��������ڴ��У��ӽ��̿��Ե���ʹ��
*/

#include <stdio.h>
#include "zmq.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

void* dcre_policy_working(void * arg){
	printf("我是子线程, 线程ID: %ld\n", pthread_self());
    //1.初始化zmq
	//2.循环监听zmq 的 ipc:///tmp/.job_dcre
	
}

static int dcre_load_policy_init() {
	//1.创建线程
	pthread_t tid;
	int ret = 0;
	ret = pthread_create(&tid, NULL, dcre_policy_working, NULL);

	if (!ret) {
		printf("创建线程成功\n");
		printf("子线程ID :%ld\n",tid);
	}
	return 0;
}

int main() {
	//初始化
	int ret = 0;
	ret = dcre_load_policy_init();
	if (ret < 0) {
		printf("初始化策略维系线程失败！\n");
		return 0;
	}
	printf("初始化策略维系线程成功!\n");
	for (int i =0; i< 100; i++) {
		printf("主线程:%d\n",i);
	}
	return 0;
}