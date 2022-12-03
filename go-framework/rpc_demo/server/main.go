package main

import (
	"fmt"
	"net"
	"net/rpc"
)

type Hello struct{

}
/*
1. 方法只能有两个可序列化的参数，其中第二个参数是指针类型
req   表示获取客户端传过来的数据
res   表示给客户端返回的数据
2. 方法返回一个error，同时必须是公开的方法
req和res的类型不能是：channel（通道）、complex(复数类型)、func(函数)
*/
func (this Hello) SayHello(req string, res *string) {
	*res = "你好" + req
	return nil
}

func main(){
	//1，注册RPC服务
	err := rpc.RegisterName("hello", new(Hello))
	if err != nil {
		fmt.Println(err)
	}
	//2.监听端口
	listener,err1 := net.Listen("tcp", "127.0.0.1:8080")
	if err1 != nil {
		fmt.Println(err1)
	}
	//3.应用退出的时候关闭监听端口
	defer listener.Close()

	for {
		//4.建立连接
		conn, err2 := listener.Accept()
		if err2 != nil{
			fmt.Println(err2)
		}
		//5.绑定服务
		rpc.ServeConn(conn)
	}
}