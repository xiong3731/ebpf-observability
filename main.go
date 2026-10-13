package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel bpf bpf/flow.bpf.c

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("exit", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ifaceName := flag.String("iface", "", "要挂载的网卡；为空时按环境变量 NODE_IP 查找")
	listen := flag.String("listen", ":9435", "metrics 监听地址")
	portList := flag.String("ports", "", "只统计这些本地端口，逗号分隔；为空统计所有入站连接")
	maxFlows := flag.Uint("max-flows", 131072, "同时跟踪的连接数上限，应大于节点并发连接数")
	maxPairs := flag.Uint("max-pairs", 65536, "(src_ip, dst_ip, toa_ip) 组合上限，即 Prometheus 时间序列规模")
	flag.Parse()

	ports, err := parsePorts(*portList)
	if err != nil {
		return err
	}
	iface, err := findIface(*ifaceName, os.Getenv("NODE_IP"))
	if err != nil {
		return err
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	spec.Maps["flows"].MaxEntries = uint32(*maxFlows)
	spec.Maps["pairs"].MaxEntries = uint32(*maxPairs)
	if uint32(len(ports)) > spec.Maps["ports"].MaxEntries {
		return fmt.Errorf("-ports 最多 %d 个", spec.Maps["ports"].MaxEntries)
	}
	if len(ports) > 0 {
		if err := spec.Variables["filter_ports"].Set(uint8(1)); err != nil {
			return fmt.Errorf("set filter_ports: %w", err)
		}
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier: %+v", ve)
		}
		return fmt.Errorf("load objects: %w", err)
	}
	defer objs.Close()

	for _, p := range ports {
		if err := objs.Ports.Put(p, uint8(1)); err != nil {
			return fmt.Errorf("put port %d: %w", p, err)
		}
	}

	// TCX link 跟随进程 fd：进程退出（包括崩溃）程序自动从网卡卸载
	for _, a := range []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{{objs.TcIngress, ebpf.AttachTCXIngress}, {objs.TcEgress, ebpf.AttachTCXEgress}} {
		l, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: a.prog, Attach: a.attach})
		if err != nil {
			return fmt.Errorf("attach %s to %s: %w", a.attach, iface.Name, err)
		}
		defer l.Close()
	}
	slog.Info("attached", "iface", iface.Name, "ports", ports, "max_flows", *maxFlows, "max_pairs", *maxPairs)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		&pairCollector{pairs: objs.Pairs},
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	slog.Info("serving", "addr", *listen)

	select {
	case err := <-errCh:
		return fmt.Errorf("http: %w", err)
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func parsePorts(s string) ([]uint16, error) {
	var ports []uint16
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := strconv.ParseUint(f, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("invalid port %q", f)
		}
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

// 指定了网卡名就用它，否则找配置了 nodeIP 的网卡
func findIface(name, nodeIP string) (*net.Interface, error) {
	if name != "" {
		return net.InterfaceByName(name)
	}
	ip := net.ParseIP(nodeIP)
	if ip == nil {
		return nil, fmt.Errorf("需要 -iface 或合法的 NODE_IP 环境变量，当前 NODE_IP=%q", nodeIP)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("没有网卡配置了 %s", nodeIP)
}
