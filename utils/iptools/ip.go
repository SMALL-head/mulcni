package iptools

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

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

func MacAddrSlice2Array6(mac net.HardwareAddr) ([6]byte, error) {
	var res [6]byte
	if len(mac) < 6 {
		return [6]byte{}, errors.New("mac addr len less than 6")
	}
	for i := 0; i < 6; i++ {
		res[i] = mac[i]
	}

	return res, nil
}

func GetInterfaceByIpaddr(ipAddr string) (*net.Interface, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddr)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var currentIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				currentIP = v.IP
			case *net.IPAddr:
				currentIP = v.IP
			}
			if currentIP.Equal(ip) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found with IP address: %s", ipAddr)
}

// GetInterfaceByIpv4Cidr 根据cidr获取对应的网卡信息
//
// cidrStr 示例： 192.168.31.3/23
func GetInterfaceByIpv4Cidr(cidrStr string) (*net.Interface, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			// 需要判断addr是否是ipv4
			s := addr.String()
			ip, ipnet, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			if ip.To4() == nil {
				continue
			}
			if ipNet.String() == ipnet.String() {
				return &iface, nil
			}
		}
	}
	return nil, errors.New("cannot find interface by cidr")
}

func GetInterfaceByDstIP(dstIP string) (*net.Interface, error) {
	conn, err := net.Dial("udp", dstIP+":80")
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP.String()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip := strings.Split(addr.String(), "/")[0]
			if ip == localIP {
				return &iface, nil
			}
		}
	}
	return nil, errors.New("cannot find interface by dstIP")
}
