package main

import (
	"fmt"
	"net/rpc"
)

func main() {
	
	//1. ��rpc.Dial��rpc΢����������
	conn, err := rpc.Dial("tcp","127.0.0.1:8080")
	if err != nil {
		fmt.Println(err1)
	}
	//2.�����˳�ʱ��Ҫ�ر�����
	defer conn.Close()

	//2.����Զ�̺���
	var reply string 

	err = conn.Call("hello.Helloworld","����",&reply)
	if err != nil {
		fmt.Println("Call:",err)
		return
	}
	fmt.Println(reply)

}