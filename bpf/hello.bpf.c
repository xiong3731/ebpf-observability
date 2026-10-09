#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#define TC_ACT_OK 0


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



SEC("tc")
int hello(struct __sk_buff *skb)
{
    __u32 key = 0;
    // 通过 bpf_map_lookup_elem，在 map pkt_states 里找到 key = 0 对应的 value（一个 struct stats）的地址。
    struct stats *s = bpf_map_lookup_elem(&pkt_states, &key);
    if (!s)
        return TC_ACT_OK;
    s->packets++;
    s->bytes += skb->len;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";