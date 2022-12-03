package main

import (
	"fmt"
	"net/rpc"
)

func main() {
	
	//1. 用rpc.Dial和rpc微服务建立连接
	conn, err := rpc.Dial("tcp","127.0.0.1:8080")
	if err != nil {
		fmt.Println(err1)
	}
	//2.函数退出时候要关闭连接
	defer conn.Close()

	//2.调用远程函数
	var reply string 

	err = conn.Call("hello.Helloworld","张三",&reply)
	if err != nil {
		fmt.Println("Call:",err)
		return
	}
	fmt.Println(reply)

}