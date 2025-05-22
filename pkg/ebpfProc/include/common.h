
// 在文件顶部添加这个宏定义
#define safe_printk(msg) ({ char _fmt[] = msg; bpf_trace_printk(_fmt, sizeof(_fmt)); })

#define bpf_memcpy __builtin_memcpy