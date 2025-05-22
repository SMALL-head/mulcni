package test_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestXxx(t *testing.T) {

	ifaceName := "h-ns2"
	link, err := netlink.LinkByName(ifaceName)
	require.NoError(t, err)
	veth, ok := link.(*netlink.Veth)
	if !ok {
		t.Fatalf("Link is not a Veth interface")
	}

	fmt.Printf("%v\n", veth.HardwareAddr)
}
