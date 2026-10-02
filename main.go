package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel hello bpf/hello.bpf.c

import (
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	index, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("网卡:", index.Name, "索引:", index.Index)

	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer objs.Close()
	fmt.Println("BPF程序加载成功")

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: index.Index,
		Program:   objs.Hello,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer l.Close()

	fmt.Println("已挂载到", index.Name, "ingress")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt) // 收到 Ctrl+C 时，往 sig 里发一个值
	<-sig                            // 阻塞在这里，直到收到值

	fmt.Println("\n退出，自动卸载")

}
