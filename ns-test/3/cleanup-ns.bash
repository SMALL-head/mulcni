ip netns delete ns3

# cleanup veth pair if it exists
if ip link show h-ns3 &>/dev/null; then
    ip link del h-ns3
fi
if ip link show cic-host &>/dev/null; then
    ip link del cic-host
fi