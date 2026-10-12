#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

struct stats {
    __u64 packets;
    __u64 bytes;
};
struct flow_counters {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
};
// 全部流量的总计数，只有一个格子，每个 CPU 各一份
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} total_stats SEC(".maps");

struct flow_key {
    __be32 local_ip;   // 网络字节序，Go 那边再转换
    __be32 remote_ip;
    __u16 local_port;    // 已用 bpf_ntohs 转成主机字节序
    __u16 remote_port;
};



// 按连接计数，所有 CPU 共用一份
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, struct flow_counters);
} flows SEC(".maps");

// 公共逻辑。egress: 0 = 收到的包，1 = 发出的包
static __always_inline int handle(struct __sk_buff *skb, int egress)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 以太网头在包的最开头
    struct ethhdr *eth = data;
    // 边界检查：以太网头的结尾不能超出包的结尾
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // IP 头紧跟在以太网头后面（偏移 14）
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)   // 6，vmlinux.h 里的 enum 有这个值
        return TC_ACT_OK;
    if (ip->ihl < 5)                   // ihl 最小是 5（20 字节），小于 5 是畸形包
        return TC_ACT_OK;

    // TCP 头在 IP 头后面，IP 头长度是 ihl * 4
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("%s %pI4:%d -> %pI4:%d", egress ? "OUT" : "IN",
               &ip->saddr, bpf_ntohs(tcp->source),
               &ip->daddr, bpf_ntohs(tcp->dest));
    bpf_printk("   S=%d A=%d F=%d R=%d P=%d len=%d",
               tcp->syn, tcp->ack, tcp->fin, tcp->rst, tcp->psh, skb->len);

    // 总计数：PERCPU，每个 CPU 改自己那份，直接 ++ 没问题
    __u32 zero = 0;
    struct stats *total = bpf_map_lookup_elem(&total_stats, &zero);
    if (!total)
        return TC_ACT_OK;
    total->packets++;
    total->bytes += skb->len;

    // 按连接计数：key 先清零，避免 padding 里有随机值
    struct flow_key key = {};
    if (egress == 1)  {
        key.local_ip = ip->saddr;
        key.remote_ip = ip->daddr;
        key.local_port = bpf_ntohs(tcp->source);
        key.remote_port = bpf_ntohs(tcp->dest);
    } else{
        key.local_ip = ip->daddr;
        key.remote_ip = ip->saddr;
        key.local_port = bpf_ntohs(tcp->dest);
        key.remote_port = bpf_ntohs(tcp->source);
    }


    struct flow_counters *val = bpf_map_lookup_elem(&flows, &key);
    if (!val) {
        // 第一次见到这个连接：先插入一行全 0 的，再查一次拿到它的地址
        struct flow_counters zero_counters = {};
        bpf_map_update_elem(&flows, &key, &zero_counters, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&flows, &key);
        if (!val)
            return TC_ACT_OK;
    }

    // 按方向选好要累加的字段，后面只写一份
    __u64 *pkts  = egress ? &val->tx_packets : &val->rx_packets;
    __u64 *bytes = egress ? &val->tx_bytes   : &val->rx_bytes;

    // 所有 CPU 共用这一行，要用原子加法
    __sync_fetch_and_add(pkts, 1);
    __sync_fetch_and_add(bytes, skb->len);

    return TC_ACT_OK;
}

// 挂到 ingress
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return handle(skb, 0);
}

// 挂到 egress
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return handle(skb, 1);
}

char _license[] SEC("license") = "GPL";
