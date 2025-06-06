ip netns delete myns

# cleanup veth pair if it exists
if ip link show h-myns1 &>/dev/null; then
    ip link del h-myns1
fi

if ip link show h-myns2 &>/dev/null; then
    ip link del h-myns2
fi

# cleanup virtual gateway
if ip link show cic-host1 &>/dev/null; then
    ip link del cic-host1
fi
if ip link show cic-host2 &>/dev/null; then
    ip link del cic-host2
fi