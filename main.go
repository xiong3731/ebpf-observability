package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel bpf bpf/flow.bpf.c

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
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("网卡:", iface.Name, "索引:", iface.Index)

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer objs.Close()
	fmt.Println("BPF程序加载成功")

	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer ingress.Close()
	fmt.Println("已挂载到", iface.Name, "ingress")

	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer egress.Close()
	fmt.Println("已挂载到", iface.Name, "egress")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	ticker := time.NewTicker(time.Second) // 每秒往 ticker.C 里发一个值
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 总计数：PERCPU map 读出来是每个 CPU 一份，要自己加起来
			var perCPU []bpfStats
			if err := objs.TotalStats.Lookup(uint32(0), &perCPU); err != nil {
				fmt.Println("读取 total_stats 失败:", err)
				continue
			}
			var total bpfStats
			for _, s := range perCPU {
				total.Packets += s.Packets
				total.Bytes += s.Bytes
			}
			fmt.Printf("累计包数: %d, 累计字节数: %d\n", total.Packets, total.Bytes)

			// 按连接计数：逐行遍历 flows
			var key bpfFlowKey      // 用来接收每一行的 key
			var val bpfFlowCounters // 用来接收每一行的 value
			iter := objs.Flows.Iterate()
			for iter.Next(&key, &val) {
				fmt.Printf("Local: %s:%d <-> Remote: %s:%d  receive 包数=%d 字节=%d ; send 包数=%d 字节=%d\n",
					ipStr(key.LocalIp), key.LocalPort,
					ipStr(key.RemoteIp), key.RemotePort,
					val.RxPackets, val.RxBytes, val.TxPackets, val.TxBytes)
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

// 把 BPF 里存的 IPv4 地址（网络字节序）转换成 "10.34.152.32" 这样的字符串
func ipStr(addr uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IP(b).String()
}
