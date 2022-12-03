package main

import "fmt"

type Usber interface {
	start()
	stop()
}

type Phone struct{
	name string
}

func (p Phone) start() {
	fmt.Println(p.name,"启动")
}
func (p Phone) stop() {
	fmt.Println(p.name,"关机")
}
func main() {
	p := Phone{
		name : "华为",
	}

	var c Usber = p

	c.start()
	c.stop()
}