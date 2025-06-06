#!/bin/zsh
ip netns delete ovs-ns1
ip netns delete ovs-ns2
ovs-vsctl del-port br0 b-v1
ovs-vsctl del-port br0 b-v2
ovs-vsctl del-br br0
