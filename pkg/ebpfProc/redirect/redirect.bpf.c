//go:build ignore

// #include "vmlinux.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/bpf_perf_event.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>      // iphdr定义
#include <linux/in.h>      // 添加此头文件获取协议常量定义
#include <bpf/bpf_endian.h>
#include "redirect.h"
#include "common.h"

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} dummy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} hashmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("xdp/dummy")
int xdp_dummy(struct xdp_md *ctx)
{
    // 更新一下hashmap的值，并且打印
    __u32 key = 1;
    __u32 value = 1;
    bpf_map_update_elem(&hashmap, &key, &value, BPF_ANY);
    __u32* lookup_res = bpf_map_lookup_elem(&hashmap, &key);
    if (lookup_res) {
        bpf_printk("hashmap value: %u\n", *lookup_res);
    } else {
        bpf_printk("hashmap lookup failed\n");
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_drop_ip(struct xdp_md *ctx)
{
    // This is a placeholder for the XDP program
    // The actual implementation would go here

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 解析以太网首部
    struct ethhdr *eth = data;
    if ((void *)(eth + 1 ) > data_end) {
        return XDP_PASS;
    }
    // 解析IP首部
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_analyse(struct xdp_md *ctx)
{
    // This is a placeholder for the XDP program
    // The actual implementation would go here

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 解析以太网首部
    struct ethhdr *eth = data;
    if ((void *)(eth + 1 ) > data_end) {
        return XDP_PASS;
    }
    // 解析IP首部
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    __u32 src = ip->saddr;
    __u32 dst = ip->daddr;
    
    struct event e = {};
    e.src = src;
    e.dst = dst;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return XDP_PASS;
}

// SEC("tc")
// int tc_ingress_redirect(struct __sk_buff *skb)
// {   
//     // 获取数据包数据
//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;
    
//     // 解析以太网头部
//     struct ethhdr *eth = data;
//     if ((void *)(eth + 1) > data_end) {
//         safe_printk("ethhdr error\n");
//         return TC_ACT_OK;
//     }
    
//     // 检查是否为 IP 包
//     if (skb->protocol != bpf_htons(ETH_P_IP)) {
//         // char fmt[] = "not ip packet: %d, expect: %d, skb->protocal: %d\n";
//         // bpf_trace_printk(fmt, sizeof(fmt), skb->protocol, bpf_htons(ETH_P_IP), bpf_ntohs(skb->protocol));
//         return TC_ACT_OK;
//     }
    
//     // 解析 IP 头部
//     struct iphdr *ip = (struct iphdr *)(eth + 1);
//     if ((void *)(ip + 1) > data_end) {
//         // safe_printk("iphdr error\n");
//         return TC_ACT_OK;
//     }
    
//     // 检查是否为 ICMP 协议
//     if (ip->protocol == IPPROTO_ICMP) {
//         // 简化：打印IP地址的点分十进制表示
//         __u32 src_addr = ip->saddr;
//         __u32 dst_addr = ip->daddr;
        
//         // 使用最简单的方式打印，避免格式化问题
//         char fmt1[] = "ICMP packet detected\n";
//         bpf_trace_printk(fmt1, sizeof(fmt1));
//         char fmt2[] = "src=%u\n";
//         bpf_trace_printk(fmt2, sizeof(fmt2), src_addr);
//         char fmt3[] = "dst=%u\n";
//         bpf_trace_printk(fmt3, sizeof(fmt3), dst_addr);
//     }

//     return TC_ACT_OK;
// }

char __license[] SEC("license") = "Dual MIT/GPL";