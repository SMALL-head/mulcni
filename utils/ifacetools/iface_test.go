package ifacetools_test

import (
	"testing"

	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/stretchr/testify/require"
)

func TestCreateVethInNs(t *testing.T) {
	info, err := ifacetools.CreateVethInNs("/var/run/netns/ns3", "h-ns3", "v-ns3", "192.168.31.4/32")
	require.NoError(t, err)
	require.Equal(t, info.IfaceNameHost, "h-ns3")
}
