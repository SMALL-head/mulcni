
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

struct dipVxlanValue {
    __u32 ifaceIndex[8]; // 最多8个接口
    __u32 vxlanIP[8]; // 与上面的接口一一对应
};