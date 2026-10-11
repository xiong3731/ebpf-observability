package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel hello bpf/hello.bpf.c

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

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
		Program:   objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer l.Close()

	fmt.Println("已挂载到", index.Name, "ingress")

	le, err := link.AttachTCX(link.TCXOptions{
		Interface: index.Index,
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer le.Close()
	fmt.Println("已挂载到", index.Name, "egress")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	ticker := time.NewTicker(time.Second) // 每秒往 ticker.C 里发一个值
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var perCPUStats []helloStats
			if err := objs.PktStates.Lookup(uint32(0), &perCPUStats); err != nil {
				fmt.Println("读取 map 失败:", err)
				continue
			}
			var total helloStats
			for _, s := range perCPUStats {
				total.Packets += s.Packets
				total.Bytes += s.Bytes
			}

			fmt.Printf("累计包数: %d, 累计字节数: %d\n", total.Packets, total.Bytes)
			var fk helloFlowKey // 用来接收每一行的 key
			var fv helloStats   // 用来接收每一行的 value
			iter := objs.Flows.Iterate()
			for iter.Next(&fk, &fv) {
				fmt.Printf("  %s:%d -> %s:%d  包数=%d 字节=%d\n",
					ipStr(fk.Saddr), fk.Source,
					ipStr(fk.Daddr), fk.Dest,
					fv.Packets, fv.Bytes)
			}
			if err := iter.Err(); err != nil {
				fmt.Println("遍历 flows 失败:", err)
			}
		case <-sig:
			fmt.Println("\n退出，自动卸载")
			return
		}
	}

}

func ipStr(addr uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IP(b).String()
}
