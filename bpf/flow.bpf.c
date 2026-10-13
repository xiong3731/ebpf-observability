#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 纯观测：返回 UNSPEC（TCX_NEXT），让同一网卡上后面的程序和协议栈继续处理
#define TC_ACT_UNSPEC   (-1)
#define ETH_P_IP        0x0800
#define IP_OFFSET_MASK  0x1fff
#define TCPOPT_TOA      254
#define TCPOLEN_IP4_TOA 8
#define TCP_OPT_MAX     40
// TOA 只在建连阶段出现，入向前几个包里没找到就认定没有 TOA
#define TOA_PARSE_PKTS  3

// Go 端加载前改写：非 0 时只统计 ports 里的本地端口
volatile const __u8 filter_ports = 0;

struct flow_key {
    __be32 local_ip;     // 网络字节序
    __be32 remote_ip;
    __u16 local_port;    // 主机字节序
    __u16 remote_port;
};

// 按连接的发起方 / 接收方聚合，不含端口，控制时间序列数量
struct pair_key {
    __be32 src_ip;       // 发起连接的一方（发 SYN 的），网络字节序
    __be32 dst_ip;       // 接受连接的一方
    __be32 toa_ip;       // TOA 里的真实客户端 IP，连接没带 TOA 时为 0
};

struct pair_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 connections;
};

struct flow_state {
    __be32 toa_ip;
    __u8 parsed;         // 已尝试解析 TOA 的入向包数
    __u8 settled;        // TOA 已确定（有或没有），之后直接计入 pairs
    __u16 pad;
    struct pair_stats pending;    // TOA 确定前的计数先暂存在这里
};

struct toa_ip4_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
};

struct toa_ctx {
    __u8 opts[64];
    __u32 opt_len;
    __u32 off;
    int found;
    struct toa_ip4_data toa;
};

// 只记录由入向 SYN 建立的连接（本机是服务端），容量由 Go 端 -max-flows 设置
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flows SEC(".maps");

// Go 端直接导出成 Prometheus counter，容量由 -max-pairs 设置
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pair_key);
    __type(value, struct pair_stats);
} pairs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} ports SEC(".maps");

static long parse_one_opt(__u32 i, struct toa_ctx *c)
{
    __u32 off = c->off;
    if (off >= c->opt_len || off >= TCP_OPT_MAX) return 1;
    __u8 kind = c->opts[off & 63];
    if (kind == 0) return 1;                         // EOL
    if (kind == 1) { c->off++; return 0; }           // NOP
    if (off + 1 >= c->opt_len) return 1;
    __u8 len = c->opts[(off + 1) & 63];
    if (len < 2) return 1;
    if (kind == TCPOPT_TOA && len == TCPOLEN_IP4_TOA) {
        // off+8 <= opt_len <= 40，所以 off <= 32，读 opts[off..off+7] 不越界
        if (off + TCPOLEN_IP4_TOA > c->opt_len || off > TCP_OPT_MAX - TCPOLEN_IP4_TOA) return 1;
        __builtin_memcpy(&c->toa, &c->opts[off], sizeof(c->toa));
        c->found = 1;
        return 1;
    }
    c->off = off + len;
    return 0;
}

// 从 TCP Option 里找 IPv4 TOA，找到返回 1
static __always_inline int parse_toa(struct __sk_buff *skb, struct tcphdr *tcp, void *data, __be32 *ip)
{
    __u32 opt_len = tcp->doff * 4;
    if (opt_len <= 20 || opt_len > 60)
        return 0;
    struct toa_ctx c = {};
    c.opt_len = opt_len - 20;
    if (bpf_skb_load_bytes(skb, (void *)(tcp + 1) - data, c.opts, c.opt_len) != 0)
        return 0;
    bpf_loop(TCP_OPT_MAX, parse_one_opt, &c, 0);
    if (!c.found)
        return 0;
    *ip = c.toa.ip;
    return 1;
}

static __always_inline void add_stats(struct pair_stats *s, int egress, __u64 len)
{
    if (egress) {
        __sync_fetch_and_add(&s->tx_packets, 1);
        __sync_fetch_and_add(&s->tx_bytes, len);
    } else {
        __sync_fetch_and_add(&s->rx_packets, 1);
        __sync_fetch_and_add(&s->rx_bytes, len);
    }
}

// egress: 0 = 收到的包，1 = 发出的包
static __always_inline int handle(struct __sk_buff *skb, int egress)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (ip->protocol != IPPROTO_TCP || ip->ihl < 5)
        return TC_ACT_UNSPEC;
    if (ip->frag_off & bpf_htons(IP_OFFSET_MASK))    // 非首个分片没有 TCP 头
        return TC_ACT_UNSPEC;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_UNSPEC;

    struct flow_key key = {};
    if (egress) {
        key.local_ip = ip->saddr;
        key.remote_ip = ip->daddr;
        key.local_port = bpf_ntohs(tcp->source);
        key.remote_port = bpf_ntohs(tcp->dest);
    } else {
        key.local_ip = ip->daddr;
        key.remote_ip = ip->saddr;
        key.local_port = bpf_ntohs(tcp->dest);
        key.remote_port = bpf_ntohs(tcp->source);
    }

    if (filter_ports && !bpf_map_lookup_elem(&ports, &key.local_port))
        return TC_ACT_UNSPEC;

    // 入向 SYN = 新的入站连接，覆盖掉同四元组的旧记录（端口复用）
    if (!egress && tcp->syn && !tcp->ack) {
        struct flow_state init = {};
        bpf_map_update_elem(&flows, &key, &init, BPF_ANY);
    }
    struct flow_state *st = bpf_map_lookup_elem(&flows, &key);
    if (!st)    // 本机主动发起的连接，或 exporter 启动前就建立的连接
        return TC_ACT_UNSPEC;

    int just_settled = 0;
    if (!st->settled) {
        if (!egress) {
            __be32 toa_ip;
            st->parsed++;
            if (parse_toa(skb, tcp, data, &toa_ip)) {
                st->toa_ip = toa_ip;
                st->settled = just_settled = 1;
            } else if (st->parsed >= TOA_PARSE_PKTS) {
                st->settled = just_settled = 1;    // 没有 TOA，toa_ip 保持 0
            }
        }
        if (!st->settled) {
            // 握手阶段的包天然串行，这里不用原子操作
            if (egress) { st->pending.tx_packets++; st->pending.tx_bytes += skb->len; }
            else        { st->pending.rx_packets++; st->pending.rx_bytes += skb->len; }
            return TC_ACT_UNSPEC;
        }
    }

    // 只跟踪入站连接，所以发起方一定是对端
    struct pair_key pk = { .src_ip = key.remote_ip, .dst_ip = key.local_ip, .toa_ip = st->toa_ip };
    struct pair_stats *cs = bpf_map_lookup_elem(&pairs, &pk);
    if (!cs) {
        struct pair_stats zero = {};
        bpf_map_update_elem(&pairs, &pk, &zero, BPF_NOEXIST);
        cs = bpf_map_lookup_elem(&pairs, &pk);
        if (!cs)
            return TC_ACT_UNSPEC;
    }

    // TOA 刚确定：把暂存的握手计数并入，记一次新连接
    if (just_settled) {
        __sync_fetch_and_add(&cs->rx_packets, st->pending.rx_packets);
        __sync_fetch_and_add(&cs->rx_bytes, st->pending.rx_bytes);
        __sync_fetch_and_add(&cs->tx_packets, st->pending.tx_packets);
        __sync_fetch_and_add(&cs->tx_bytes, st->pending.tx_bytes);
        __sync_fetch_and_add(&cs->connections, 1);
        __builtin_memset(&st->pending, 0, sizeof(st->pending));
    }

    add_stats(cs, egress, skb->len);
    return TC_ACT_UNSPEC;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return handle(skb, 0);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return handle(skb, 1);
}

char _license[] SEC("license") = "GPL";
