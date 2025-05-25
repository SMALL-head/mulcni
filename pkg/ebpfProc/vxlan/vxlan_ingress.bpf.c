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

struct bpf_elf_map __section("maps") ip2Iface = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct ipDstKey),
	.size_value	= sizeof(struct ipDstValue),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 4096,
};


// 这里说一下vxlan收包这边的逻辑：当一个vxlan包从源节点到达目标节点后，这个包会被解封装。
// 由于vxlan包是一个UDP包，因此到达目标主机后，首先会到一个进程中，该进程端口号为8472(vxlan默认端口号)
// 然后解封装后，将原来包的内容转发给vxlan网络接口
SEC("classifier")
int vxlan_ingress(struct __sk_buff *skb)
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

    __u32 dst_ip = bpf_htonl(ip->daddr);

    struct ipDstKey key = {0};
    key.da = dst_ip;
    struct ipDstValue *value = bpf_map_lookup_elem(&ip2Iface, &key);
    if (!value) {
        // 该da找不到dst ip对应的veth信息
        return TC_ACT_OK;
    }
    bpf_skb_change_type(skb, PACKET_HOST);
    __u8 dst_mac[ETH_ALEN] = {0};
    bpf_memcpy(dst_mac, value->mac, ETH_ALEN);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN, 0);
    return bpf_redirect_peer(value->ifaceIndex, 0);
//    return TC_ACT_OK;
}

// 在文件末尾添加或修改为以下内容
char __license[] SEC("license") = "Dual BSD/GPL";
