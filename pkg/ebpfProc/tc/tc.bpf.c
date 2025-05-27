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

#define VXLAN_VETH_KEY 0

struct bpf_elf_map __section("maps") ip2Iface = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct ipDstKey),
	.size_value	= sizeof(struct ipDstValue),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 4096,
};

// key存放ip mask地址，value存放该ip地址对应的隧道接口索引以及该接口索引需要封装ip地址
// struct bpf_elf_map __section("maps") dipVxlan = {
//     .type = BPF_MAP_TYPE_HASH,
//     .size_key = sizeof(struct ipSrcKey),
//     .size_value = sizeof(struct dipVxlanValue),
//     .pinning = PIN_GLOBAL_NS,
//     .max_elem = 4096,
// };

// 存储vxlan veth的iface索引
struct bpf_elf_map __section("maps") vxlanIface = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 1,
};


SEC("classifier")
int tc_ingress_redirect(struct __sk_buff *skb)
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
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    // dst是否是本机上的？
    struct ipDstKey key = {};
    __u32 da = bpf_ntohl(ip->daddr);
    key.da = da;
    struct ipDstValue *v = bpf_map_lookup_elem(&ip2Iface, &key);
    if (v) {
        bpf_skb_change_type(skb, PACKET_HOST); // 直接改包类型就不会校验mac地址了，这种做法感觉很暴力，可以作为兜底。不过我还是先尝试更改mac地址
        __u8 dst_mac[ETH_ALEN];
        // bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
        bpf_memcpy(dst_mac, v->mac, ETH_ALEN);
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN, 0); // 修改目的mac地址
        return bpf_redirect_peer(v->ifaceIndex, 0); // 发送到位于ns的对端
    }

    // 如果没有在本node上找到对应的v，则直接转发给vxlan设备做进一步操作
    __u32 vxlan_key = VXLAN_VETH_KEY;
    __u32 *vxlan_device_id = bpf_map_lookup_elem(&vxlanIface, &vxlan_key);
    if (vxlan_device_id) {
        return bpf_redirect_peer(*vxlan_device_id, 0); // 发送到vxlan设备
    } else {
        trace_printk("vxlan device not found, key: %d\n", vxlan_key);
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";