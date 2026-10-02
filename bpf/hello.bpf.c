#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#define TC_ACT_OK 0

SEC("tc")
int hello(struct __sk_buff *skb)
{
    bpf_printk("Hello, eBPF!\n");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";