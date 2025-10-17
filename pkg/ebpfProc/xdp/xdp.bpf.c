//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>      // 添加此头文件获取协议常量定义
#include <linux/udp.h>
#include "common.h"

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

#define VXLAN_DST_PORT 8472
#define VXLAN_HEADER_LEN 8
#define DEFAULT_TUNNEL_ID 13001

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
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

SEC("xdp")
int xdp_strip_vxlan_redirect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    // 放行非ip数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    // 放行非udp数据包
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    unsigned ip_hdr_len = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)((void *)iph + ip_hdr_len);
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    if (udph->dest != __constant_htons(VXLAN_DST_PORT)) {
        return XDP_PASS;
    }

    void *vxlan = (void*)(udph + 1);
    if (vxlan + 8 > data_end) {
        return XDP_PASS;
    }
    __u8 *vxhdr = vxlan;
    __u32 vni = ((vxhdr[4] << 16) | (vxhdr[5] << 8) | vxhdr[6]);

    if (vni != DEFAULT_TUNNEL_ID) {
        // 不是我们期望的vni，直接放行
        bpf_printk("xdp_strip_vxlan_redirect: unexpected vni: %u\n", vni);
        return XDP_PASS;
    }

    // 计算VXLAN头的位置
    __u32 outer_eth_len = sizeof(*eth);
    __u32 outer_udp_len = sizeof(*udph);
    __u32 strip = outer_eth_len + ip_hdr_len + outer_udp_len + VXLAN_HEADER_LEN; // bytes
    int ret = bpf_xdp_adjust_head(ctx, strip);
    if (ret < 0) {
        bpf_printk("bpf_xdp_adjust_head failed: %d\n", ret);
        return XDP_PASS;
    }

    // 裁剪成功后，重新获取data和data_end指针
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // 重新解析以太网头，拿到内层ip头
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;   
    }

    struct ipDstKey key = {};
    key.da = bpf_ntohl(iph->daddr);
    // bpf_printk("xdp_strip_vxlan_redirect: lookup ip: %x\n", key.da);
    struct ipDstValue* v = bpf_map_lookup_elem(&ip2Iface, &key);
    if (!v) {
        bpf_printk("xdp_strip_vxlan_redirect: no iface found for ip: %x\n", key.da);
        return XDP_PASS;
    }
    bpf_printk("xdp_strip_vxlan_redirect: redirect to iface index: %d\n", v->ifaceIndex);
    // 重定向到ns里！！
    bpf_redirect(v->ifaceIndex, 0);
    return XDP_REDIRECT;
}


char __license[] SEC("license") = "Dual MIT/GPL";