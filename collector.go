package main

import (
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	labels       = []string{"src_ip", "dst_ip", "toa_ip"}
	descRxBytes  = prometheus.NewDesc("ebpf_tcp_rx_bytes_total", "dst 从 src 收到的字节数（含以太网头）", labels, nil)
	descRxPkts   = prometheus.NewDesc("ebpf_tcp_rx_packets_total", "dst 从 src 收到的包数（GRO 合并后）", labels, nil)
	descTxBytes  = prometheus.NewDesc("ebpf_tcp_tx_bytes_total", "dst 发给 src 的字节数（含以太网头）", labels, nil)
	descTxPkts   = prometheus.NewDesc("ebpf_tcp_tx_packets_total", "dst 发给 src 的包数（GSO 拆分前）", labels, nil)
	descConns    = prometheus.NewDesc("ebpf_tcp_connections_total", "src 向 dst 新建的连接数", labels, nil)
	descEntries  = prometheus.NewDesc("ebpf_tcp_pairs", "pairs map 当前条目数，接近 -max-pairs 时会发生 LRU 淘汰", nil, nil)
	descScrapeOK = prometheus.NewDesc("ebpf_tcp_scrape_success", "本次遍历 pairs map 是否完整", nil, nil)
)

// 每次 scrape 直接读内核 map，计数在内核里单调累加，Go 端不保存状态
type pairCollector struct {
	pairs *ebpf.Map
}

func (c *pairCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descRxBytes, descRxPkts, descTxBytes, descTxPkts, descConns, descEntries, descScrapeOK} {
		ch <- d
	}
}

func (c *pairCollector) Collect(ch chan<- prometheus.Metric) {
	var (
		k    bpfPairKey
		v    bpfPairStats
		seen = make(map[bpfPairKey]struct{})
	)
	it := c.pairs.Iterate()
	for it.Next(&k, &v) {
		// 遍历期间内核在增删条目，同一个 key 可能出现两次，重复会让 Gather 报错
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		src, dst, toa := ipStr(k.SrcIp), ipStr(k.DstIp), ""
		if k.ToaIp != 0 {
			toa = ipStr(k.ToaIp)
		}
		ch <- prometheus.MustNewConstMetric(descRxBytes, prometheus.CounterValue, float64(v.RxBytes), src, dst, toa)
		ch <- prometheus.MustNewConstMetric(descRxPkts, prometheus.CounterValue, float64(v.RxPackets), src, dst, toa)
		ch <- prometheus.MustNewConstMetric(descTxBytes, prometheus.CounterValue, float64(v.TxBytes), src, dst, toa)
		ch <- prometheus.MustNewConstMetric(descTxPkts, prometheus.CounterValue, float64(v.TxPackets), src, dst, toa)
		ch <- prometheus.MustNewConstMetric(descConns, prometheus.CounterValue, float64(v.Connections), src, dst, toa)
	}
	ok := 1.0
	if err := it.Err(); err != nil {
		slog.Warn("iterate pairs", "err", err)
		ok = 0
	}
	ch <- prometheus.MustNewConstMetric(descEntries, prometheus.GaugeValue, float64(len(seen)))
	ch <- prometheus.MustNewConstMetric(descScrapeOK, prometheus.GaugeValue, ok)
}

// BPF 里存的是网络字节序的 IPv4，按小端读出来的 uint32 原样写回字节即可
func ipStr(addr uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IP(b).String()
}
