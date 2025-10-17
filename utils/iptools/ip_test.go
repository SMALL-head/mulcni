package iptools

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIp2Uint32(t *testing.T) {
	ipStr := "10.244.2.2"
	i := net.ParseIP(ipStr)
	res, _ := Ip2Uint32(i)

	fmt.Printf("%x\n", res)
}

func TestMacAddr(t *testing.T) {
	veth, err := net.InterfaceByName("h-ns11")
	require.NoError(t, err)

	res, err := MacAddrSlice2Array6(veth.HardwareAddr)
	require.NoError(t, err)

	fmt.Println(res)
	fmt.Println(veth.Index)
}
