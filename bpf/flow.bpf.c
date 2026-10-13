#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define TCPOPT_TOA      254
#define TCPOLEN_IP4_TOA 8



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

struct flow_key {
    __be32 local_ip;   // 网络字节序，Go 那边再转换
    __be32 remote_ip;
    __u16 local_port;    // 已用 bpf_ntohs 转成主机字节序
    __u16 remote_port;
};
struct toa_ip4_data {
    __u8 kind;
    __u8 len;
    __u16 port;
    __u32 ip;
};

struct toa_ctx {
    __u8 opts[64];       // Option 区拷贝到这里
    __u32 opt_len;       // Option 区实际长度
    __u32 off;           // 当前读到哪（代替 ptr）
    int found;
    struct toa_ip4_data toa;
};

struct  toa_client {
    __be32 ip;      // 网络字节序，和 flow_key 的 ip 保持一致，Go 那边用 ipStr 转换
    __u16 port;     // 主机字节序（存之前用 bpf_ntohs 转好）
    __u16 pad;      // 手动补齐到 8 字节，这样不会有隐藏的 padding  
};


// 全部流量的总计数，只有一个格子，每个 CPU 各一份
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} total_stats SEC(".maps");

// 按连接计数，所有 CPU 共用一份
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, struct flow_counters);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, struct toa_client);
} toa_map SEC(".maps");


static long parse_one_opt(__u32 i, struct toa_ctx *c)
{
    __u32 off = c->off;
    if (off >= c->opt_len || off >= 40) return 1;   // 代替 ptr >= opt_end
    __u8 kind = c->opts[off & 63];
    if (kind == 0 ) return 1;
    if (kind == 1) {c->off++; return 0;}  // NOP：别忘了往前移，这次是改 c->off
    if (off + 1 >= c->opt_len) return 1;            // 后面还有 len 这个字节吗
    __u8 len = c->opts[(off+1) & 63] ;
    if (len <2) return 1;
    if (kind == TCPOPT_TOA && len == TCPOLEN_IP4_TOA) {
        if (off + 8 > c->opt_len) return 1;
        // 从 c->opts 的第 off 个字节开始，复制 8 个字节到 c->toa 里。
        __builtin_memcpy(&c->toa, &c->opts[off & 31], sizeof(c->toa));
        c->found=1;
        return 1;
    }
    c->off = off + len;
    return 0;
};

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


    // bpf_printk("%s %pI4:%d -> %pI4:%d", egress ? "OUT" : "IN",
    //            &ip->saddr, bpf_ntohs(tcp->source),
    //            &ip->daddr, bpf_ntohs(tcp->dest));
    // bpf_printk("   S=%d A=%d F=%d R=%d P=%d len=%d",
    //            tcp->syn, tcp->ack, tcp->fin, tcp->rst, tcp->psh, skb->len);

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

    if (tcp->syn && !tcp->ack) {                  // 新连接的第一个包，清掉旧记录
        bpf_map_delete_elem(&flows, &key);
        bpf_map_delete_elem(&toa_map, &key);
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


    if (!egress){
        if (!bpf_map_lookup_elem(&toa_map, &key)) {
            struct toa_ctx c = {};
            __u32 opt_len = tcp->doff * 4;
            if (opt_len > 20 && opt_len <= 60) {          // 有 Option，并且不是畸形包
                c.opt_len = opt_len - 20;
                // 参数的意思分别是: 包, 偏移量, 目标, 长度, 从包的第"偏移"个字节开始，拷贝"长度"个字节到"目标地址"。
                if (bpf_skb_load_bytes(skb, (void *)(tcp + 1) - data, c.opts, c.opt_len) == 0) {
                    bpf_loop(40, parse_one_opt, &c, 0);
                    if (c.found){
                        struct toa_client v = {};
                        v.ip   = c.toa.ip;
                        v.port = bpf_ntohs(c.toa.port);
                        bpf_map_update_elem(&toa_map, &key, &v, BPF_ANY);
                        // bpf_printk("TOA client %pI4:%d", &c.toa.ip, bpf_ntohs(c.toa.port));
                    }
                }
            }            
        }
        
    }   
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
