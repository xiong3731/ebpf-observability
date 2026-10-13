#!/bin/bash
# 端到端自测：veth + 普通客户端 + 用 scapy 伪造带 TOA 的客户端，检查 /metrics。
# 需要 Linux 6.6+ 的 root 环境（已在 Ubuntu 24.04 / 6.8 节点上跑通），或在特权容器里跑：
#   docker run --rm -v "$PWD":/src -w /src golang:1.26-bookworm bash -c \
#     'apt-get update && apt-get install -y clang llvm libbpf-dev && go generate && CGO_ENABLED=0 go build -o .exporter-linux .'
#   docker run --rm --privileged -v "$PWD":/src debian:bookworm bash /src/e2e.sh
set -e
apt-get update -qq >/dev/null; apt-get install -y -qq iproute2 iptables curl python3-scapy >/dev/null 2>&1
ip netns add cli
ip link add v0 type veth peer name v1
ip link set v1 netns cli
ip addr add 10.0.0.1/24 dev v0; ip link set v0 up
ip netns exec cli ip addr add 10.0.0.2/24 dev v1
ip netns exec cli ip link set v1 up; ip netns exec cli ip link set lo up
# scapy 绕过内核发包，不拦住的话内核会对 SYN-ACK 回 RST
ip netns exec cli iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
python3 -m http.server 8080 --bind 10.0.0.1 >/dev/null 2>&1 &
python3 -m http.server 9090 --bind 10.0.0.1 >/dev/null 2>&1 &
sleep 1
NODE_IP=10.0.0.1 /src/.exporter-linux -listen 127.0.0.1:9435 -ports 8080 &
trap 'kill $! 2>/dev/null' EXIT   # 不关掉的话后台进程会占着输出，ssh 不返回
# /healthz 能访问说明 BPF 已经挂到网卡上了
until curl -sf 127.0.0.1:9435/healthz >/dev/null; do sleep 0.2; done
for i in 1 2 3; do ip netns exec cli curl -s -o /dev/null http://10.0.0.1:8080/; done
ip netns exec cli curl -s -o /dev/null http://10.0.0.1:9090/   # 不在 -ports 里，不应出现
ip netns exec cli python3 - <<'PY'
from scapy.all import *
conf.verb=0
toa=[('MSS',1460),(254, bytes([0x1f,0x90,1,2,3,4]))]   # 真实客户端 1.2.3.4:8080
for sp in (40001,40002):
    sa=sr1(IP(dst='10.0.0.1')/TCP(sport=sp,dport=8080,flags='S',seq=100,options=toa),timeout=2)
    send(IP(dst='10.0.0.1')/TCP(sport=sp,dport=8080,flags='A',seq=101,ack=sa.seq+1))
    send(IP(dst='10.0.0.1')/TCP(sport=sp,dport=8080,flags='PA',seq=101,ack=sa.seq+1)/b'GET / HTTP/1.0\r\n\r\n')
    time.sleep(0.5)
PY
sleep 1
out=$(curl -s 127.0.0.1:9435/metrics | grep '^ebpf_')
echo "$out"
echo "$out" | grep -qx 'ebpf_tcp_connections_total{dst_ip="10.0.0.1",src_ip="10.0.0.2",toa_ip="1.2.3.4"} 2'
echo "$out" | grep -qx 'ebpf_tcp_connections_total{dst_ip="10.0.0.1",src_ip="10.0.0.2",toa_ip=""} 3'
echo "$out" | grep -qx 'ebpf_tcp_pairs 2'   # 9090 不在 -ports 里，不应多出条目
echo PASS
