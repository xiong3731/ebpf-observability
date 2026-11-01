package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// readEvents 在独立 goroutine 中阻塞读取；reader.Close() 会唤醒 Read。
func readEvents(reader *ringbuf.Reader) error {
	var event bpfPacketEvent
	eventSize := binary.Size(event)
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("读取 ringbuf: %w", err)
		}
		if len(record.RawSample) != eventSize {
			return fmt.Errorf("事件长度不匹配: got=%d want=%d", len(record.RawSample), eventSize)
		}
		// -target bpfel 指定小端；IP 使用字节数组，不参与整数序转换。
		if _, err := binary.Decode(record.RawSample, binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("解码事件: %w", err)
		}
		src := netip.AddrPortFrom(netip.AddrFrom4(event.SrcIp), event.SrcPort)
		dst := netip.AddrPortFrom(netip.AddrFrom4(event.DstIp), event.DstPort)
		slog.Info("packet",
			"point", observationPointName(event.Point),
			"ifindex", event.Ifindex,
			"src", src.String(), "dst", dst.String(),
			"proto", event.Protocol, "len", event.Length,
			"tcp_flags", fmt.Sprintf("0x%02x", event.TcpFlags),
			"ktime_ns", event.TimestampNs,
		)
	}
}

func observationPointName(point uint8) string {
	switch bpfObservationPoint(point) {
	case bpfObservationPointFROM_ENDPOINT:
		return "FROM_ENDPOINT"
	case bpfObservationPointTO_ENDPOINT:
		return "TO_ENDPOINT"
	case bpfObservationPointFROM_NETWORK:
		return "FROM_NETWORK"
	case bpfObservationPointTO_NETWORK:
		return "TO_NETWORK"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", point)
	}
}

// PERCPU_ARRAY 的每个 CPU 都有一个值，用户态需要求和。
func logEventDrops(drops *ebpf.Map) {
	var perCPU []uint64
	if err := drops.Lookup(uint32(0), &perCPU); err != nil {
		slog.Error("读取事件丢失计数失败", "err", err)
		return
	}
	var total uint64
	for _, count := range perCPU {
		total += count
	}
	if total > 0 {
		slog.Warn("ringbuf 事件写入失败", "dropped_total", total)
	} else {
		slog.Info("ringbuf 状态", "dropped_total", total)
	}
}
