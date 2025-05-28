package iptools

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

func Ipv4Str2Uint32(ipv4Str string) (uint32, error) {
	ip := net.ParseIP(ipv4Str)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipv4Str)
	}
	res := binary.BigEndian.Uint32(ip.To4())
	return res, nil
}

func Ip2Uint32(ip_ net.IP) (uint32, error) {
	if ip_.To4() == nil {
		return 0, fmt.Errorf("IP is not IPv4: %s", ip_.String())
	}
	return binary.BigEndian.Uint32(ip_.To4()), nil
}

// AddRouteInNS 在nnss命令空间中添加arp表项，ifaceName网卡名称需要保证在ns中能够查找到
func AddArpInNS(nnss ns.NetNS, ipStr string, ifaceName string, macAddr net.HardwareAddr) error {
	return nnss.Do(func(nn ns.NetNS) error {
		l, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return err
		}
		// 创建ARP表项
		neigh := &netlink.Neigh{
			LinkIndex:    l.Attrs().Index,
			IP:           net.ParseIP(ipStr),
			HardwareAddr: macAddr,
			State:        netlink.NUD_PERMANENT, // 设置为永久ARP表项
		}
		// 直接使用NeighSet，它会更新已存在的表项或创建新表项
		if err := netlink.NeighSet(neigh); err != nil {
			return err
		}
		return nil
	})

}
