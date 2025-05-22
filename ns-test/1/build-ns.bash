ip netns add ns1
ip netns add ns2

# 创建vethd对
ip link add v-ns1 type veth peer name h-ns1
ip link add v-ns2 type veth peer name h-ns2

# 将veth对的一个端口放入命名空间
ip link set v-ns1 netns ns1
ip link set v-ns2 netns ns2

# 命名空间内部ip地址配置，并激活veth pair与lo
ip netns exec ns1 ip addr add 192.168.31.2/32 dev v-ns1
ip netns exec ns1 ifconfig lo up
ip netns exec ns1 ifconfig v-ns1 up
# 网关添加
ip netns exec ns1 route add -net 192.168.31.1 netmask 255.255.255.255 dev v-ns1
ip netns exec ns1 route add default gw 192.168.31.1 dev v-ns1

ip netns exec ns2 ip addr add 192.168.31.3/32 dev v-ns2
ip netns exec ns2 ifconfig lo up
ip netns exec ns2 ifconfig v-ns2 up
# 网关添加
ip netns exec ns2 route add -net 192.168.31.1 netmask 255.255.255.255 dev v-ns2
ip netns exec ns2 route add default gw 192.168.31.1 dev v-ns2

# host中的激活
ifconfig h-ns1 up
ifconfig h-ns2 up
tc qdisc add dev h-ns1 clsact
tc qdisc add dev h-ns2 clsact

# 主机上的网关添加
# cic-host作为tc ebpf程序挂载的载体，cic-host-peer没啥作用，因为我希望这个ebpf程序能够重定向所有数据包或者drop不符合条件的包
ip link add cic-host type veth peer name cic-host-peer # cic-host-peer没用
ifconfig cic-host 192.168.31.1/24 up
tc qdisc add dev cic-host clsact # 添加一个可以挂载bpf程序的队列