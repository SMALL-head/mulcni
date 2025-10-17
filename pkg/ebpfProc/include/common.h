#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>      // 添加此头文件获取协议常量定义
#include <linux/udp.h>
// 在文件顶部添加这个宏定义
#define safe_printk(msg) ({ char _fmt[] = msg; bpf_trace_printk(_fmt, sizeof(_fmt)); })

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

#define bpf_memcpy __builtin_memcpy

#ifndef __section
# define __section(x) __attribute__((section(x), used))
#endif

unsigned long long load_byte(void *skb,
        unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
        unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
        unsigned long long off) asm("llvm.bpf.load.word");

#define VXLAN_TOTAL_HEADER_LEN 50 // 14(eth)+20(ip)+8(udp)+8(vxlan)
#define IP_HLEN 20
#define UDP_HLEN 8
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define IP_ID_OFF (ETH_HLEN + offsetof(struct iphdr, id))
#define IP_LEN_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))
#define TCP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define UDP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define UDP_LEN_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len))


struct ipSrcKey {
    __u32 sa;
};

struct ipDstKey {
    __u32 da;
};

struct ipDstValue {
    __u32 da;
    __u32 ifaceIndex;
    __u8 mac[ETH_ALEN];
};

struct ifaceMac {
    __u32 ipaddr;
    __u8 mac[ETH_ALEN];
};

struct dipVxlanValue {
    __u32 ifaceIndex[8]; // 最多8个接口
    __u32 vxlanIP[8]; // 存放该ip地址所在的那个node的ip地址，用于封装vxlan首部
    __u16 lb_factor; // 上述接口负载均衡因子,高8位表示有效接口数量，低8位表示负载均衡因子
};

struct vxlan_header {
    __u8 header[VXLAN_TOTAL_HEADER_LEN]; // 50 bytes
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ipDstKey);
    __type(value, struct ipDstValue);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip2Iface SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct ipDstKey);
    __type(value, struct vxlan_header);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlanHeaderMap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vxlanIface SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ipDstKey);
    __type(value, struct dipVxlanValue);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dipVxlan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct ifaceMac);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifaceMacMap SEC(".maps");

static inline int set_new_length_outerhdr(struct __sk_buff *skb, unsigned int ori_len) {
    // 1. UDP长度改写
    if ((void *)(long)skb->data_end < (void *)(long)skb->data + ETH_HLEN + IP_HLEN + UDP_HLEN) return -1;
    __u16 udp_len = __constant_htons(ori_len - ETH_HLEN - IP_HLEN);
    bpf_skb_store_bytes(skb, UDP_LEN_OFF, &udp_len, sizeof(udp_len), 0);
    // 2. IP长度改写和校验和更新
    if ((void *)(long)skb->data_end < (void *)(long)skb->data + ETH_HLEN + IP_HLEN) return -1;
    __u16 old_len = __constant_htons(load_half(skb, IP_LEN_OFF));
    __u16 ip_len = __constant_htons(ori_len - ETH_HLEN);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_len, ip_len, sizeof(ip_len));
    bpf_skb_store_bytes(skb, IP_LEN_OFF, &ip_len, sizeof(ip_len), 0);
    return 0;
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
    value->lb_factor = (valid_len << 8) | lb_factor;    // 更新负载均衡因子
    return res;                                         // 简单的轮询负载均衡
}