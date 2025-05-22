tc filter show dev h-ns1 ingress

cat /sys/kernel/debug/tracing/trace_pipe # 调试信息

# 写入arp表项
arp -s <ip地址> <mac地址>

# bpf map查找瑜信息查看
bpftool map list 
bpftool map dump id <map_id>

# 用这种方式，map才能自动挂载，
# ip link set dev h-ns1 xdp obj /sys/fs/bpf/xdp_prog -> 这种方式map好像没有创建出来
bpftool net attach xdp pinned /sys/fs/bpf/xdp_prog dev h-ns1


# tc command
tc qdisc add dev h-ns1 clsact # 添加一个可以挂载bpf程序的队列
tc qdisc show dev h-ns1 # 查看队列信息
tc filter show dev h-ns1 ingress # 查看tc filter信息（比如说挂载了哪个ebpf程序）

# watch命令
watch -d -n 1 ip -s link show dev cic-host # 查看cic-host网卡中的tx(transport)和rx(receive)信息