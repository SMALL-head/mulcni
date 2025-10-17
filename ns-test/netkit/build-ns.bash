#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# 读取 .env（忽略空行、# 与 // 开头的注释）
if [ -f "$ENV_FILE" ]; then
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*|'//'*) continue ;;
      *'='*) export "$line" ;;
    esac
  done < "$ENV_FILE"
fi

# 默认值（当 .env 未提供时）
: "${NS1:=ns1}"
: "${GATEWAY_IP1:=10.244.2.1}"
: "${GATEWAY_IP2:=10.224.2.1}"
: "${VETH1_IP:=10.244.2.2/32}"
: "${VETH2_IP:=10.224.2.2/32}"

# 创建命名空间
ip netns add "$NS1"


# 创建两对veth对(ns1)
ip link add v-ns11 type veth peer name h-ns11
ip link add v-ns12 type veth peer name h-ns12


# 将veth对的一端放入命名空间(ns1)
ip link set v-ns11 netns "$NS1"
ip link set v-ns12 netns "$NS1"

# 配置命名空间(ns1)内的第一张网卡
ip netns exec "$NS1" ip addr add "$VETH1_IP" dev v-ns11
ip netns exec "$NS1" ip link set v-ns11 up


# 配置命名空间(ns1)内的第二张网卡
ip netns exec "$NS1" ip addr add "$VETH2_IP" dev v-ns12
ip netns exec "$NS1" ip link set v-ns12 up

# 激活命名空间内的lo设备
ip netns exec "$NS1" ip link set lo up

# 配置主机端网卡
ip link set h-ns11 up
ip link set h-ns12 up

# 为命名空间中的网卡配置特定网段的路由
# ns1 配置10.244.0.0/16网段通过第一张网卡路由
ip netns exec "$NS1" ip route add "${GATEWAY_IP1}/32" dev v-ns11
ip netns exec "$NS1" ip route add 10.244.0.0/16 via "$GATEWAY_IP1" dev v-ns11

# ns1 配置10.224.0.0/16网段通过第二张网卡路由
ip netns exec "$NS1" ip route add "${GATEWAY_IP2}/32" dev v-ns12
ip netns exec "$NS1" ip route add 10.224.0.0/16 via "$GATEWAY_IP2" dev v-ns12

# 配置默认路由（如果需要，可以选择其中一个作为默认网关）
ip netns exec "$NS1" ip route add default via "$GATEWAY_IP1" dev v-ns11

# 添加TC队列（如果需要挂载eBPF程序）
tc qdisc add dev h-ns11 clsact || true
tc qdisc add dev h-ns12 clsact || true

# 验证网络配置
echo "命名空间 $NS1 内路由表:"
ip netns exec "$NS1" ip route
