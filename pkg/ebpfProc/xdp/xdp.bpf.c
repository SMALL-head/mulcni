//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} gateway SEC(".maps");

// SEC("xdp")
// int xdp_dummy(struct xdp_md *ctx)
// {
//     __u32 key = 1;
//     __u32 value = 1;
//     bpf_map_update_elem(&hashmap, &key, &value, BPF_ANY);
//     __u32* lookup_res = bpf_map_lookup_elem(&hashmap, &key);
//     if (lookup_res) {
//         bpf_printk("hashmap value: %u\n", *lookup_res);
//     } else {
//         bpf_printk("hashmap lookup failed\n");
//     }
//     return XDP_PASS;
// }

SEC("xdp")
int xdp_redirect_gateway(struct xdp_md *ctx)
{
    // 目前的策略是所有的数据包都转发给网关,网关的序号应该由用户态的通过map告知 
    __u32 key = 0;
    __u32 *value = bpf_map_lookup_elem(&gateway, &key);
    if (!value) {
        // 如果没有找到对应的网关，直接丢弃数据包
        bpf_printk("xdp_redirect_gateway: no gateway found\n");
        return XDP_PASS;
    }
    bpf_printk("xdp_redirect_gateway: %u\n", *value);
    return bpf_redirect(*value, 0);
}


char __license[] SEC("license") = "Dual MIT/GPL";