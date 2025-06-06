#!/bin/bash

# 创建命名空间
ip netns add myns

# 创建两对veth对
ip link add v-myns1 type veth peer name h-myns1
ip link add v-myns2 type veth peer name h-myns2

# 将veth对的一端放入命名空间
ip link set v-myns1 netns myns
ip link set v-myns2 netns myns

# 配置命名空间内的第一张网卡 (10.244.2.2/32)
ip netns exec myns ip addr add 10.244.2.2/32 dev v-myns1
ip netns exec myns ip link set v-myns1 up

# 配置命名空间内的第二张网卡 (10.224.2.2/32)
ip netns exec myns ip addr add 10.224.2.2/32 dev v-myns2
ip netns exec myns ip link set v-myns2 up

# 激活命名空间内的lo设备
ip netns exec myns ip link set lo up

# 配置主机端网卡
ip link set h-myns1 up
ip link set h-myns2 up

# 为命名空间中的网卡配置特定网段的路由
# 配置10.244.0.0/16网段通过第一张网卡路由
ip netns exec myns ip route add 10.244.2.1/32 dev v-myns1
ip netns exec myns ip route add 10.244.0.0/16 via 10.244.2.1 dev v-myns1

# 配置10.224.0.0/16网段通过第二张网卡路由
ip netns exec myns ip route add 10.224.2.1/32 dev v-myns2
ip netns exec myns ip route add 10.224.0.0/16 via 10.224.2.1 dev v-myns2

# 配置默认路由（如果需要，可以选择其中一个作为默认网关）
ip netns exec myns ip route add default via 10.244.2.1 dev v-myns1

# 添加TC队列（如果需要挂载eBPF程序）
tc qdisc add dev h-myns1 clsact
tc qdisc add dev h-myns2 clsact

# 验证网络配置
# echo "命名空间内网卡配置:"
# ip netns exec myns ip addr

echo "命名空间内路由表:"
ip netns exec myns ip route
