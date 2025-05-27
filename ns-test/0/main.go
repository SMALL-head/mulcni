// 该文件测试各种sdk方法是否是我预期中的结果
package main

import (
	"github.com/SMALL-head/mulcni/utils/iptools"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func main() {
	AddRouteInNS()
}

// 测试向ns中的添加arp表项
func AddRouteInNS() {
	ns1, _ := ns.GetNS("/var/run/netns/ns1")
	cicHost, err := netlink.LinkByName("cic-host")
	if err != nil {
		panic(err)
	}
	cicHostLink := cicHost.(*netlink.Veth)

	// 获取cicHostLink的IP信息
	addrs, err := netlink.AddrList(cicHostLink, netlink.FAMILY_V4)
	if err != nil {
		panic(err)
	}

	if len(addrs) == 0 {
		panic("No IP address found")
	}
	// 这里假设我们只取第一个IP地址
	cicHostIpAddr := addrs[0]

	// 获取cicHostLink的MAC地址
	cicHostMAC := cicHostLink.Attrs().HardwareAddr
	cicHostIP := cicHostIpAddr.IP

	logrus.Infof("尝试添加ARP表项: IP=%s, MAC=%s", cicHostIP.String(), cicHostMAC.String())

	err = iptools.AddArpInNS(ns1, cicHostIP.String(), "v-ns1", cicHostMAC)
	if err != nil {
		logrus.Errorf("Failed to add ARP entry: %v", err)
	}
}
