//go:build ignore
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/in.h>      // 添加此头文件获取协议常量定义
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>

#include <linux/if_packet.h>
#include "common.h"

#define DEFAULT_TUNNEL_ID 13001


// 用于选择远端点，key为远端node对应的子网ip，value为该子网ip可以选择的网卡信息
struct bpf_elf_map __section("maps") dipVxlan = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct ipDstKey),
    .size_value = sizeof(struct dipVxlanValue),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 4096,
};


SEC("classifier")
int vxlan_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        // char fmt[] = "not ip packet: %d, expect: %d, skb->protocal: %d\n";
        // bpf_trace_printk(fmt, sizeof(fmt), skb->protocol, bpf_htons(ETH_P_IP), bpf_ntohs(skb->protocol));
        return TC_ACT_UNSPEC;
    }
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    // 确保IP头部完全在数据包内
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    __u32 dst_ip = bpf_htonl(ip->daddr);

    struct ipDstKey key = {0};
    // key.da = dst_ip;
    __u32 mask = 0xFFFFF000;
    __u32 masked_ip = dst_ip & mask;
    key.da = masked_ip;
    struct dipVxlanValue *value = bpf_map_lookup_elem(&dipVxlan, &key);
    if (!value) {
        // 该da找不到对应的node信息，无法继续封装vxlan
        return TC_ACT_OK;
    }
    // 封装vxlan包
    __u32 ifaceIndex = 0; // 网卡负载均衡
    struct bpf_tunnel_key tunnel_key;
    __builtin_memset(&tunnel_key, 0, sizeof(tunnel_key));

    tunnel_key.remote_ipv4 = value->vxlanIP[ifaceIndex];
    tunnel_key.tunnel_id = DEFAULT_TUNNEL_ID;
    tunnel_key.tunnel_tos = 0;
    tunnel_key.tunnel_ttl = 64;

    int ret = bpf_skb_set_tunnel_key(skb, &tunnel_key, sizeof(tunnel_key), BPF_F_ZERO_CSUM_TX);
    if (ret < 0) {
        trace_printk("bpf_skb_set_tunnel_key failed: %d\n", ret);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

// 在文件末尾添加或修改为以下内容
char __license[] SEC("license") = "Dual BSD/GPL";
