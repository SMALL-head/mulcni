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
static __u32 choose_iface_index(struct dipVxlanValue *valueu);

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
    trace_printk("vxlan egress: skb->protocol: %d\n", skb->protocol);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        trace_printk("vxlan egress: eth header not complete\n");
        return TC_ACT_OK;
    }

    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        // char fmt[] = "not ip packet: %d, expect: %d, skb->protocal: %d\n";
        // bpf_trace_printk(fmt, sizeof(fmt), skb->protocol, bpf_htons(ETH_P_IP), bpf_ntohs(skb->protocol));
        trace_printk("vxlan egress: not an IP packet, protocol: %d\n", skb->protocol);
        return TC_ACT_UNSPEC;
    }
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    // 确保IP头部完全在数据包内
    if ((void *)(ip + 1) > data_end) {
        trace_printk("vxlan egress: ip header not complete\n");
        return TC_ACT_OK;
    }
    __u32 dst_ip = bpf_htonl(ip->daddr);

    struct ipDstKey key = {0};
    // key.da = dst_ip;
    __u32 mask = 0xFFFFFF00;
    __u32 masked_ip = dst_ip & mask;
    key.da = masked_ip;
    struct dipVxlanValue *value = bpf_map_lookup_elem(&dipVxlan, &key);
    if (!value) {
        // 该da找不到对应的node信息，无法继续封装vxlan
        trace_printk("vxlan egress: no dst ip found for %x\n", dst_ip);
        return TC_ACT_OK;
    }
    // 封装vxlan包
    __u32 ifaceIndex = choose_iface_index(value); // 网卡负载均衡
    if (ifaceIndex >= 8) {
        trace_printk("vxlan egress: ifaceIndex out of range: %d\n", ifaceIndex);
        return TC_ACT_OK; // 如果ifaceIndex不在范围内，直接返回
    }
    
    struct bpf_tunnel_key tunnel_key;
    __builtin_memset(&tunnel_key, 0, sizeof(tunnel_key));

    tunnel_key.remote_ipv4 = value->vxlanIP[ifaceIndex];
    trace_printk("vxlan egress: remote_ipv4: %x\n", tunnel_key.remote_ipv4);
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

static __u32 choose_iface_index(struct dipVxlanValue *value) {
    // value空校验请在调用函数前进行
    if (!value) {
        return 0;
    }
    __u8 valid_len = (value->lb_factor & 0xFF00) >> 8;  // 高8位表示有效接口数量
    __u8 lb_factor = value->lb_factor & 0x00FF;         // 低8位表示负载均衡因子
    __u32 res = lb_factor;                              // 简单的轮询负载均衡
    lb_factor = (lb_factor + 1) % valid_len;
    return res;                                         // 简单的轮询负载均衡
    
}

// 在文件末尾添加或修改为以下内容
char __license[] SEC("license") = "Dual BSD/GPL";
