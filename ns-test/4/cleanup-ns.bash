ip netns delete ns1

# cleanup veth pair if it exists
if ip link show h-ns11 &>/dev/null; then
    ip link del h-ns11
fi

if ip link show h-ns12 &>/dev/null; then
    ip link del h-ns12
fi

# cleanup virtual gateway
if ip link show cic-host1 &>/dev/null; then
    ip link del cic-host1
fi
if ip link show cic-host2 &>/dev/null; then
    ip link del cic-host2
fi