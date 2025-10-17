//go:build ignore
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/in.h>      // 添加此头文件获取协议常量定义
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>

#include <linux/if_packet.h>
#include "common.h"

#define VXLAN_VETH_KEY 0
#define DEFAULT_TUNNEL_ID 13001
#define VXLAN_DST_PORT 8472
#define VXLAN_UDP_SRC_PORT 12345
#define VXLAN_HEADER_LEN 8

// struct bpf_elf_map __section("maps") ip2Iface = {
// 	.type		= BPF_MAP_TYPE_HASH,
// 	.size_key	= sizeof(struct ipDstKey),
// 	.size_value	= sizeof(struct ipDstValue),
// 	.pinning	= PIN_GLOBAL_NS,
// 	.max_elem	= 4096,
// };

// key存放ip mask地址，value存放该ip地址对应的隧道接口索引以及该接口索引需要封装ip地址
// struct bpf_elf_map __section("maps") dipVxlan = {
//     .type = BPF_MAP_TYPE_HASH,
//     .size_key = sizeof(struct ipSrcKey),
//     .size_value = sizeof(struct dipVxlanValue),
//     .pinning = PIN_GLOBAL_NS,
//     .max_elem = 4096,
// };

// 存储vxlan veth的iface索引
// struct bpf_elf_map __section("maps") vxlanIface = {
//     .type = BPF_MAP_TYPE_HASH,
//     .size_key = sizeof(__u32),
//     .size_value = sizeof(__u32),
//     .pinning = PIN_GLOBAL_NS,
//     .max_elem = 1,
// };


SEC("classifier/redirect")
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
    bpf_skb_change_type(skb, PACKET_HOST); // 直接改包类型就不会校验mac地址了，这种做法感觉很暴力，可以作为兜底。不过我还是先尝试更改mac地址
    if (v) {
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
        trace_printk("vxlan device found, key: %d, iface index: %d\n", vxlan_key, *vxlan_device_id);
        return bpf_redirect(*vxlan_device_id, 0); // 发送到vxlan设备，对于该函数而言，如果不指定flag，那么数据包将会发送到target的egress hook中
    } else {
        trace_printk("vxlan device not found, key: %d\n", vxlan_key);
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
}


SEC("classifier/redirect_directly")
int tc_ingress_redirect_directly(struct __sk_buff *skb)
{   
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    unsigned ip_hdr_len = ip->ihl * 4;
    struct udphdr *udph = (struct udphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(udph + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (udph->dest != __constant_htons(VXLAN_DST_PORT)) {
        return TC_ACT_OK;
    }
    void *vxlan = (void*)(udph + 1);
    if (vxlan + 8 > data_end) {
        return TC_ACT_OK;
    }
    __u8 *vxhdr = vxlan;
    __u32 vni = ((vxhdr[4] << 16) | (vxhdr[5] << 8) | vxhdr[6]);
    if (vni != DEFAULT_TUNNEL_ID) {
        // 不是我们期望的vni，直接放行
        trace_printk("tc_ingress_redirect_ddirecly: unexpected vni: %u\n", vni);
        return TC_ACT_OK;
    }

    // 计算VXLAN头的位置
    __u32 outer_eth_len = sizeof(*eth);
    __u32 outer_udp_len = sizeof(*udph);
    __u32 strip = outer_eth_len + ip_hdr_len + outer_udp_len + VXLAN_HEADER_LEN; // bytes

    int ret = bpf_skb_adjust_room(skb, -strip, BPF_ADJ_ROOM_MAC, 0); // 裁剪vxlan首部
    if (ret < 0) {
        trace_printk("bpf_skb_adjust_room failed: %d\n", ret);
        return TC_ACT_OK;
    }

    // 裁剪成功后，重新获取data和data_end指针
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    // 重新解析以太网头，拿到内层ip头
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }
    struct ipDstKey key = {};
    key.da = bpf_ntohl(ip->daddr);
    struct ipDstValue *v = bpf_map_lookup_elem(&ip2Iface, &key);
    if (!v) {
        trace_printk("tc_ingress_redirect_ddirecly: no iface found for ip: %x\n", key.da);
        return TC_ACT_OK;
    }
    // trace_printk("tc_ingress_redirect_direcly: redirect to iface index: %d\n", v->ifaceIndex);
    return bpf_redirect_peer(v->ifaceIndex, 0); // 重定向到ns里！！
}

SEC("classifier/vxlan")
int tc_ingress_vxlan(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_OK;
    }

    struct ipDstKey key = {};
    __u32 da = bpf_ntohl(iph->daddr);
    key.da = da;
    struct ipDstValue *v = bpf_map_lookup_elem(&ip2Iface, &key);
    
    if (v) {
        __u8 dst_mac[ETH_ALEN];
        bpf_skb_change_type(skb, PACKET_HOST); // 直接改包类型就不会校验mac地址了，这种做法感觉很暴力，可以作为兜底。不过我还是先尝试更改mac地址
        // bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
        bpf_memcpy(dst_mac, v->mac, ETH_ALEN);
        bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN, 0); // 修改目的mac地址
        return bpf_redirect_peer(v->ifaceIndex, 0); // 发送到位于ns的对端   
    }

    // 非本机的ip，查阅是否需要封vxlan包
    // __u32 mask = 0xFFFFFF00;
    // __u32 masked_ip = da & mask;
    // key.da = masked_ip;
    struct dipVxlanValue *value = bpf_map_lookup_elem(&dipVxlan, &key);
    if (!value) {
        // 该da找不到对应的node信息，无法继续封装vxlan
        trace_printk("tc_ingress_vxlan: no dst ip found for %x\n", da);
        return TC_ACT_OK;   
    }

    // 封装vxlan包
    __u32 ifaceIndex = choose_iface_index(value); // 网卡负载均衡
    if (ifaceIndex >= 8) {
        trace_printk("tc_ingress_vxlan: ifaceIndex out of range: %d\n", ifaceIndex);
        return TC_ACT_OK; // 如果ifaceIndex不在范围内，直接返回
    }

    // 外层vxlan相关的首部一共50字节，包括一层mac一层ip一层udp和vxlan头
    // long err = bpf_skb_adjust_room(skb, 50, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO | 
    //     BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | 
    //     BPF_F_ADJ_ROOM_ENCAP_L4_UDP | 
    //     BPF_F_ADJ_ROOM_ENCAP_L2(14) | 
    //     BPF_F_ADJ_ROOM_ENCAP_L2_ETH);
    // if (err < 0) {
    //     return TC_ACT_OK;
    // }

    long err = bpf_skb_adjust_room(skb, 50, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4);
    if (err < 0) {
        return TC_ACT_OK;
    }

    __u32 nodeIP = value->vxlanIP[ifaceIndex];
    key.da = nodeIP;
    struct vxlan_header *vxlan_hdr = bpf_map_lookup_elem(&vxlanHeaderMap, &key);
    if (!vxlan_hdr) {
        trace_printk("tc_ingress_vxlan: no vxlan header found for ip: %x\n", nodeIP);
        return TC_ACT_OK;
    }

    // 将50bytes的vxlan头写入包头
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if (data + 64 > data_end) {
        trace_printk("tc_ingress_vxlan: data + 64 > data_end\n");
        return TC_ACT_OK;
    }

    // 将data[0:14]复制到内层mac首部
    eth = data + 50;
    bpf_memcpy(eth, data, 14); 

    // 拷贝vxlan首部
    bpf_memcpy(data, vxlan_hdr->header, 50);

    // 修改外层mac源地址。由于本层有负载均衡所有src地址只有到本ebpf prog中才能拿到
    struct ifaceMac* ifMac = bpf_map_lookup_elem(&ifaceMacMap, &value->ifaceIndex[ifaceIndex]);
    trace_printk("tc_ingress_vxlan: value->ifaceIndex[%d]=%d\n", ifaceIndex, value->ifaceIndex[ifaceIndex]);
    if (!ifMac) {
        trace_printk("tc_ingress_vxlan: no iface mac found for iface index: %d\n", value->ifaceIndex[ifaceIndex]);
        return TC_ACT_OK;
    }
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), ifMac->mac, ETH_ALEN, 0); // 修改源mac地址

    int update_outer_header_res = set_new_length_outerhdr(skb, skb->len); // 这个版本的libbpf对于bpf_skb_store_bytes函数严格要求其只能在返回值为int的函数中被调用
    if (update_outer_header_res < 0) {
        trace_printk("tc_ingress_vxlan: set_new_length_outerhdr failed: %d\n", update_outer_header_res);
        // return TC_ACT_OK;
    }

    // 添加外层ip src地址
    __u32 src_ip = bpf_htonl(ifMac->ipaddr);
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &src_ip, sizeof(src_ip), 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, 0, src_ip, sizeof(src_ip));

    // TODO: 打印新的封装首部做debug，我写的代码绝对是错的，打完日志再运行
    // 按字节打印各首部（ETH/IP/UDP/VXLAN）
    // __u32 off_eth   = 0;
    // __u32 off_ip    = off_eth + (__u32)sizeof(struct ethhdr);
    // __u32 off_udp   = off_ip  + (__u32)20;
    // __u32 off_vxlan = off_udp + (__u32)sizeof(struct udphdr);

    // // ETH: 14字节
    // bpf_printk("ETH hdr bytes:");
    // #pragma unroll
    // for (int i = 0; i < 14; i++) {
    //     __u8 b = 0;
    //     if (bpf_skb_load_bytes(skb, off_eth + i, &b, 1) == 0) {
    //         bpf_printk("ETH[%02d]=0x%02x", i, (__u64)b);
    //     }
    // }

    // // IP: 20
    // bpf_printk("IP hdr bytes (len=%u):", (__u64)20);
    // #pragma unroll
    // for (int i = 0; i < 20; i++) {
    //     __u8 b = 0;
    //     if (bpf_skb_load_bytes(skb, off_ip + i, &b, 1) == 0) {
    //         bpf_printk("IP[%02d]=0x%02x", i, (__u64)b);
    //     }
    // }

    // // UDP: 8字节
    // bpf_printk("UDP hdr bytes:");
    // #pragma unroll
    // for (int i = 0; i < 8; i++) {
    //     __u8 b = 0;
    //     if (bpf_skb_load_bytes(skb, off_udp + i, &b, 1) == 0) {
    //         bpf_printk("UDP[%02d]=0x%02x", i, (__u64)b);
    //     }
    // }

    // // VXLAN: 8字节 + VNI
    // bpf_printk("VXLAN hdr bytes:");
    // #pragma unroll
    // for (int i = 0; i < 8; i++) {
    //     __u8 b = 0;
    //     if (bpf_skb_load_bytes(skb, off_vxlan + i, &b, 1) == 0) {
    //         bpf_printk("VX[%02d]=0x%02x", i, (__u64)b);
    //     }
    // }
    return bpf_redirect(value->ifaceIndex[ifaceIndex], 0);
}

char __license[] SEC("license") = "Dual MIT/GPL";