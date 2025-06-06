#!/bin/zsh
ip netns add ovs-ns1
ip netns add ovs-ns2

ip link add v-v1 type veth peer name b-v1
ip link add v-v2 type veth peer name b-v2
ip link set v-v1 netns ovs-ns1
ip link set v-v2 netns ovs-ns2
ovs-vsctl add-br br0
ifconfig br0 up
ovs-vsctl add-port br0 b-v1
ovs-vsctl add-port br0 b-v2
ifconfig b-v1 up
ifconfig b-v2 up

ip netns exec ovs-ns1 ifconfig v-v1 192.168.31.4/16 up
ip netns exec ovs-ns2 ifconfig v-v2 192.168.31.5/16 up

# vxlan
ovs-vsctl add-port br0 tun0 -- set interface tun0 type=vxlan options:local_ip=10.176.40.187 options:remote_ip=flow options:key=flow
ovs-ofctl add-flow br0 'table=0,priority=200,ip,nw_dst=192.168.31.0/24 action=normal' # 自己家的流量
ovs-ofctl add-flow br0 'table=0,priority=200,ip,nw_dst=192.168.32.0/24 actions=set_field:10.176.40.188->tun_dst,normal'
ovs-ofctl add-flow br0 'table=0,priority=200,arp,arp_op=1 actions=set_field:10.176.40.188->tun_dst,output:normal'
ovs-ofctl add-flow br0 'table=0,priority=200,arp,arp_op=2 actions=set_field:10.176.40.188->tun_dst,output:normal'
ovs-ofctl add-flow br0 'table=0,priority=200,arp,actions=normal'