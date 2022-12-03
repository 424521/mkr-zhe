package main

import (
	"fmt"
	"time"
	"sync"
)

func main() {
	ch := make(chan int, 3)

	ch  <- 10
}



















// var wg sync.WaitGroup

// func test(n int) {
// 	for num := (n - 1)*30000 + 1; num < n * 30000; num ++ {
// 		var flag = true
// 		for i := 2; i < num; i++ {
// 			if num%i == 0{
// 				flag = false
// 				break
// 			}
// 		}
// 		if flag{

// 		}
// 	} 
// 	wg.Done()
// }

// func main() {
// 	start := time.Now().Unix()
// 	for i := 1; i < 4; i++ {
// 		wg.Add(1)
// 		go test(i)
// 	}
// 	wg.Wait()
// 	end := time.Now().Unix()
// 	fmt.Println("全部执行完毕,共用时", end - start,"ms")
// }






















// func main(){
// 	start := time.Now().Unix()
// 	for num:=2; num < 12000; num ++ {
// 		var flag = true
// 		for i:=2; i < num; i++ {
// 			if num%i == 0 {
// 				flag = false
// 				break
// 			}
// 		}
// 		if flag {
// 			fmt.Println(num,"是素数")
// 		}
// 	}
// 	end := time.Now().Unix()
// 	fmt.Println("程序运行总共用时：",end - start,"ms")
	
// }