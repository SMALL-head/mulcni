package ifacetools_test

import (
	"net"
	"testing"

	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestCreateVethInNs(t *testing.T) {
	info, err := ifacetools.CreateVethInNs("/var/run/netns/ns3", "h-ns3", "v-ns3", "192.168.31.4/32")
	require.NoError(t, err)
	require.Equal(t, info.IfaceNameHost, "h-ns3")
	// 测试完毕，删除veth pair
	// netlink.LinkDel()
}

func TestInfo(t *testing.T) {
	l, err := netlink.LinkByName("vethdd3e983")
	require.NoError(t, err)
	vethHost := l.(*netlink.Veth)
	require.Equal(t, 0, int(vethHost.LinkAttrs.Flags&net.FlagUp))
}

func TestShouldSkip(t *testing.T) {
	ns3, err := ns.GetNS("/var/run/netns/ns3")
	require.NoError(t, err)
	ns3.Do(func(hostNs ns.NetNS) error {
		return hostNs.Do(func(_ ns.NetNS) error {
			l, err := netlink.LinkByName("h-ns3")
			require.NoError(t, err)
			err = netlink.LinkSetUp(l)
			require.NoError(t, err)
			return nil

		})
	})
}
