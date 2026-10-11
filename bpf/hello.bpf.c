#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

struct stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} pkt_states SEC(".maps");


struct flow_key{
    __be32 saddr;
    __be32 daddr;
    __u16 source;
    __u16 dest;
};

struct {
    __uint(type,BPF_MAP_TYPE_LRU_HASH );
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, struct stats);
}flows SEC(".maps");

static __always_inline int handle(struct __sk_buff *skb, int egress){
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 读包：以太网头就在包的最开头
    struct ethhdr *eth = data;
    // 边界检查：以太网头的结尾不能超出包的结尾
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;   
    // bpf_printk("proto=0x%x", eth->h_proto);

    // 取第15个字节
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)   // 6，vmlinux.h 里的 enum 有这个值
        return TC_ACT_OK;

    if (ip->ihl < 5)                          // ihl 最小是 5（20 字节），小于 5 是畸形包
        return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("%s %pI4:%d -> %pI4:%d",egress ? "OUT":"IN",
            &ip->addrs.saddr, bpf_ntohs(tcp->source),
            &ip->addrs.daddr, bpf_ntohs(tcp->dest));

    bpf_printk("   S=%d A=%d F=%d R=%d P=%d len=%d",tcp->syn, tcp->ack, tcp->fin, tcp->rst, tcp->psh, skb->len);
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&pkt_states, &key);
    if (!s)
        return TC_ACT_OK;
    s->packets++;
    s->bytes += skb->len;


    struct flow_key fkey = {};
    fkey.saddr= ip->addrs.saddr;
    fkey.daddr= ip->addrs.daddr;
    fkey.source=bpf_ntohs(tcp->source);
    fkey.dest=bpf_ntohs(tcp->dest);

    struct stats *fs=bpf_map_lookup_elem(&flows, &fkey);
    if (!fs){
        struct stats init={};
        init.packets=1;
        init.bytes = skb->len;
        bpf_map_update_elem(&flows,&fkey,&init,BPF_NOEXIST);
    }else{
        __sync_fetch_and_add(&fs->packets,1);
        __sync_fetch_and_add(&fs->bytes,skb->len);
    }


    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return handle(skb,0);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return handle(skb,1);
}

char _license[] SEC("license") = "GPL";