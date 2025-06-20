#!/bin/bash

# 创建命名空间
ip netns add ns1


# 创建两对veth对(ns1)
ip link add v-ns11 type veth peer name h-ns11
ip link add v-ns12 type veth peer name h-ns12


# 将veth对的一端放入命名空间(ns1)
ip link set v-ns11 netns ns1
ip link set v-ns12 netns ns1

# 配置命名空间(ns1)内的第一张网卡 (10.244.2.2/32)
ip netns exec ns1 ip addr add 10.244.2.2/32 dev v-ns11
ip netns exec ns1 ip link set v-ns11 up


# 配置命名空间(ns1)内的第二张网卡 (10.224.2.2/32)
ip netns exec ns1 ip addr add 10.224.2.2/32 dev v-ns12
ip netns exec ns1 ip link set v-ns12 up

# 激活命名空间内的lo设备
ip netns exec ns1 ip link set lo up

# 配置主机端网卡
ip link set h-ns11 up
ip link set h-ns12 up

# 为命名空间中的网卡配置特定网段的路由
# ns1 配置10.244.0.0/16网段通过第一张网卡路由
ip netns exec ns1 ip route add 10.244.2.1/32 dev v-ns11
ip netns exec ns1 ip route add 10.244.0.0/16 via 10.244.2.1 dev v-ns11

# ns1 配置10.224.0.0/16网段通过第二张网卡路由
ip netns exec ns1 ip route add 10.224.2.1/32 dev v-ns12
ip netns exec ns1 ip route add 10.224.0.0/16 via 10.224.2.1 dev v-ns12

# 配置默认路由（如果需要，可以选择其中一个作为默认网关）
ip netns exec ns1 ip route add default via 10.244.2.1 dev v-ns11

# 添加TC队列（如果需要挂载eBPF程序）
tc qdisc add dev h-ns11 clsact
tc qdisc add dev h-ns12 clsact

# 验证网络配置
# echo "命名空间内网卡配置:"
# ip netns exec ns1 ip addr

echo "ns1命名空间内路由表:"
ip netns exec ns1 ip route

# echo "ns2命名空间内路由表:"
# ip netns exec ns2 ip route
