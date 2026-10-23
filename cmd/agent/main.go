//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel bpf ../../bpf/flow.bpf.c

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const (
	// pollInterval 是接口全量 dump 的周期。调试时可临时改成 5 * time.Second。
	pollInterval = 30 * time.Second
	// probeIP 只用于让内核回答"默认路由走哪块网卡"，不会真的发包。
	probeIP = "8.8.8.8"
)

// linkClass 是接口在 Layer 0 里的角色。
type linkClass string

const (
	classPod       linkClass = "POD"
	classNode      linkClass = "NODE"
	classSkipSlave linkClass = "SKIP(slave)"
	classSkipLoop  linkClass = "SKIP(loopback)"
	classSkipOther linkClass = "SKIP(other)"
)

// endpointKey 是内核视角的接口身份（retina types_linux.go:163）。
// 不用 ifindex：netnsid 会被内核回收复用，三元组能区分重建的接口。
type endpointKey struct {
	name  string
	mac   string
	netns int
}

func keyOf(a *netlink.LinkAttrs) endpointKey {
	return endpointKey{name: a.Name, mac: a.HardwareAddr.String(), netns: a.NetNsID}
}

func (k endpointKey) logArgs() []any {
	return []any{"iface", k.name, "mac", k.mac, "netnsid", k.netns}
}

type attachment struct {
	ingress link.Link
	egress  link.Link
}

type attacher struct {
	mu   sync.Mutex
	have map[endpointKey]*attachment
}

func newAttacher() *attacher {
	return &attacher{have: make(map[endpointKey]*attachment)}
}

// attachLocked 幂等挂载 ingress + egress。调用者必须持有 at.mu。
func (at *attacher) attachLocked(l netlink.Link, objs *bpfObjects) error {
	a := l.Attrs()
	k := keyOf(a)
	if _, ok := at.have[k]; ok {
		return nil
	}

	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: a.Index,
		Program:   objs.TcIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(), // 先于策略程序执行，被丢弃的包也能看到
	})
	if err != nil {
		return fmt.Errorf("attach ingress: %w", err)
	}

	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: a.Index,
		Program:   objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Head(),
	})
	if err != nil {
		_ = ingress.Close()
		return fmt.Errorf("attach egress: %w", err)
	}

	at.have[k] = &attachment{ingress: ingress, egress: egress}
	return nil
}

// detachLocked 幂等卸载。先删表项再 Close；Close 失败只记日志，
// 否则"接口已被内核回收"这类正常情况会让 key 永远卡在 have 里。
func (at *attacher) detachLocked(k endpointKey) {
	am, ok := at.have[k]
	if !ok {
		return
	}
	delete(at.have, k)

	if err := am.ingress.Close(); err != nil {
		slog.Warn("关闭 ingress link 失败", append(k.logArgs(), "err", err)...)
	}
	if err := am.egress.Close(); err != nil {
		slog.Warn("关闭 egress link 失败", append(k.logArgs(), "err", err)...)
	}
}

func (at *attacher) closeAll() {
	at.mu.Lock()
	defer at.mu.Unlock()
	for k := range at.have {
		at.detachLocked(k)
	}
}

// sync 执行一轮 dump → 分类 → diff → attach/detach。
func (at *attacher) sync(links []netlink.Link, nodeIface string, objs *bpfObjects) {
	at.mu.Lock()
	defer at.mu.Unlock()

	type target struct {
		link  netlink.Link
		class linkClass
	}
	want := make(map[endpointKey]target)
	for _, l := range links {
		if c := classify(l, nodeIface); c == classPod || c == classNode {
			want[keyOf(l.Attrs())] = target{link: l, class: c}
		}
	}

	for k, t := range want {
		if _, ok := at.have[k]; ok {
			continue
		}
		if err := at.attachLocked(t.link, objs); err != nil {
			// 不记入 have，下一轮自然重试
			slog.Error("挂载失败", append(k.logArgs(), "class", t.class, "err", err)...)
			continue
		}
		slog.Info("endpoint created",
			append(k.logArgs(), "class", t.class, "ifindex", t.link.Attrs().Index)...)
	}

	for k := range at.have {
		if _, ok := want[k]; ok {
			continue
		}
		at.detachLocked(k)
		slog.Info("endpoint deleted", k.logArgs()...)
	}
}

func run() error {
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return fmt.Errorf("加载 BPF: %w", err)
	}
	defer objs.Close()
	slog.Info("BPF 程序已加载")

	at := newAttacher()
	defer at.closeAll()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 只算一次：某轮 RouteGet 临时失败不应该导致节点口被卸载
	nodeIface, err := defaultOutgoingIface()
	if err != nil {
		slog.Warn("未找到默认出接口，只观测 Pod 流量", "err", err)
	} else {
		slog.Info("默认出接口", "iface", nodeIface)
	}

	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("LinkList: %w", err)
	}
	logInventory(links, nodeIface)
	at.sync(links, nodeIface, objs)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("收到退出信号，开始卸载")
			return nil
		case <-ticker.C:
			links, err := netlink.LinkList()
			if err != nil {
				slog.Error("LinkList 失败，下一轮重试", "err", err)
				continue
			}
			at.sync(links, nodeIface, objs)
		}
	}
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	if err := run(); err != nil {
		slog.Error("agent 退出", "err", err)
		os.Exit(1)
	}
}

func logInventory(links []netlink.Link, nodeIface string) {
	counts := make(map[linkClass]int)
	for _, l := range links {
		a := l.Attrs()
		c := classify(l, nodeIface)
		counts[c]++
		slog.Info("link",
			"ifindex", a.Index,
			"name", a.Name,
			"type", l.Type(),
			"mac", a.HardwareAddr.String(),
			"netnsid", a.NetNsID,
			"parent", a.ParentIndex,
			"master", a.MasterIndex,
			"class", c,
		)
	}
	slog.Info("接口清点",
		"pod", counts[classPod],
		"node", counts[classNode],
		"skip", counts[classSkipSlave]+counts[classSkipLoop]+counts[classSkipOther],
	)
}

func classify(l netlink.Link, nodeIface string) linkClass {
	a := l.Attrs()
	switch {
	case l.Type() == "veth":
		return classPod
	case a.MasterIndex != 0:
		return classSkipSlave
	case a.Flags&net.FlagLoopback != 0:
		return classSkipLoop
	case a.Name == nodeIface:
		return classNode
	default:
		return classSkipOther
	}
}

// defaultOutgoingIface 让内核回答：去 probeIP 走哪块网卡。
// 这是路由查询，不会真的发包，也不依赖外网可达。
func defaultOutgoingIface() (string, error) {
	routes, err := netlink.RouteGet(net.ParseIP(probeIP))
	if err != nil {
		return "", fmt.Errorf("RouteGet %s: %w", probeIP, err)
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("RouteGet %s: 无匹配路由", probeIP)
	}
	l, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", fmt.Errorf("LinkByIndex %d: %w", routes[0].LinkIndex, err)
	}
	return l.Attrs().Name, nil
}
