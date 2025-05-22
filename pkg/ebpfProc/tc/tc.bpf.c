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

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

struct ipSrcKey {
    __u32 sa;
};

struct ipDstValue {
    __u32 da;
    __u32 ifaceIndex;
    __u8 mac[ETH_ALEN];
};

#ifndef __section
# define __section(x) __attribute__((section(x), used))
#endif

struct bpf_elf_map __section("maps") ip2Iface = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct ipSrcKey),
	.size_value	= sizeof(struct ipDstValue),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 4096,
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
        char fmt[] = "not ip packet: %d, expect: %d, skb->protocal: %d\n";
        bpf_trace_printk(fmt, sizeof(fmt), skb->protocol, bpf_htons(ETH_P_IP), bpf_ntohs(skb->protocol));
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    if (ip->protocol == IPPROTO_ICMP) {
        // test whether the map can be used
        // __u32 sa = bpf_ntohl(ip->saddr);
        struct ipSrcKey key = {};
        __u32 da = bpf_ntohl(ip->daddr);
        key.sa = da;
        struct ipDstValue *v = bpf_map_lookup_elem(&ip2Iface, &key);
        if (!v) {
            return TC_ACT_OK;
        }

        bpf_skb_change_type(skb, PACKET_HOST); // 直接改包类型就不会校验mac地址了，这种做法感觉很暴力，可以作为兜底。不过我还是先尝试更改mac地址

        __u8 dst_mac[ETH_ALEN];
        // bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
        bpf_memcpy(dst_mac, v->mac, ETH_ALEN);
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN, 0); // 修改目的mac地址

        return bpf_redirect_peer(v->ifaceIndex, 0); // 发送到位于ns的对端
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";