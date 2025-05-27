package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/SMALL-head/mulcni/pkg/ebpfProc/tc"
	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/SMALL-head/mulcni/utils/iptools"
	"github.com/SMALL-head/mulcni/utils/tctools"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// gatewayIPStr 是网关的IP地址,不带掩码位
func initNS(nsName string, gateWayIPStr string, tcIngressBPFProgPath string) (cleanup func(), err error) {
	ns1, err := ns.GetNS(fmt.Sprintf("/var/run/netns/%s", nsName))
	if err != nil {
		logrus.Errorf("Failed to get %s: %v", nsName, err)
		return nil, err
	}

	// veth pair
	vIp, vIpNet, err := net.ParseCIDR("10.244.2.2/32")
	if err != nil {
		logrus.Fatalf("Failed to parse CIDR: %v", err)
	}
	vIpNet.IP = vIp

	vethInfo, err := ifacetools.CreateVethInNs(
		fmt.Sprintf("/var/run/netns/%s", nsName),
		fmt.Sprintf("h-%s", nsName),
		fmt.Sprintf("v-%s", nsName),
		vIpNet.String())
	if err != nil {
		if err.Error() == "file exists" {
			logrus.Infof("veth pair \"%s\"<->\"%s\" already exists", vethInfo.IfaceNameHost, vethInfo.IfaceNameNs)
		} else {
			logrus.Fatalf("Failed to create veth pair in ns: %v", err)
		}
	}
	err = tctools.AddClsactQdiscIntoDev(vethInfo.IfaceNameHost)
	if err != nil {
		logrus.Errorf("Failed to add clsact qdisc into device %s: %v", vethInfo.IfaceNameHost, err)
	}

	// host主机中的veth pair
	cicHost, cicHostPeer, err := ifacetools.CreateVethPair("cic-host", "cic-host-peer")
	if err != nil {
		if err.Error() == "file exists" {
			logrus.Infof("veth pair \"cic-host\"<->\"cic-host-peer\" already exists")
		} else {
			logrus.Fatalf("Failed to create host gateway veth pair: %v", err)
		}
	}
	gatewayIP, gatewayIpNet, _ := net.ParseCIDR(fmt.Sprintf("%s/24", gateWayIPStr))
	gatewayIpNet.IP = gatewayIP
	netlink.AddrAdd(cicHost, &netlink.Addr{IPNet: gatewayIpNet})
	netlink.LinkSetUp(cicHost)
	netlink.LinkSetUp(cicHostPeer)

	// 添加路由信息
	ns1.Do(func(_ ns.NetNS) error {
		// route add -net {gatewayip} netmask 255.255.255.255 dev {veth_name}
		gatewayIpForRoute, gatewatIfNetForRoute, _ := net.ParseCIDR(fmt.Sprintf("%s/32", gateWayIPStr))
		gatewatIfNetForRoute.IP = gatewayIpForRoute
		if err := netlink.RouteAdd(&netlink.Route{
			Dst:       gatewatIfNetForRoute,
			LinkIndex: vethInfo.LinkIndexNs,
			Scope:     netlink.SCOPE_LINK,
		}); err != nil {
			logrus.Errorf("Failed to add route in ns: %v", err)
			return err
		}
		// route add default gw {gatewayip} dev {veth_name}
		if err := netlink.RouteAdd(&netlink.Route{
			Gw:        gatewayIpForRoute,
			LinkIndex: vethInfo.LinkIndexNs,
		}); err != nil {
			logrus.Errorf("Failed to add default route in ns: %v", err)
			return err
		}

		return nil
	})

	// arp 表项添加
	err = iptools.AddArpInNS(ns1, gateWayIPStr, vethInfo.IfaceNameNs, cicHost.HardwareAddr)
	if err != nil {
		logrus.Errorf("Failed to add ARP entry in ns: %v", err)
		return nil, err
	}

	// 搭建vxlan设备
	vxlanl, err := ifacetools.CreateVxlanAndUp("cic-vxlan")
	if err != nil {
		logrus.Errorf("Failed to create vxlan device: %v", err)
		return nil, err
	}

	// 将vxlan设备信息添加到ebpf map中
	vxlanIfaceMap := tc.MountMap("vxlanIface", "", 1, uint32(0), uint32(0))
	err = vxlanIfaceMap.Put(uint32(0), uint32(vxlanl.Index))
	if err != nil {
		logrus.Errorf("Failed to put vxlan iface index into map: %v", err)
	}

	// tc ingress ebpf程序挂载到ns host端的veth上
	err = tctools.AttachIngressBPFToIface(vethInfo.IfaceNameHost, tcIngressBPFProgPath)
	if err != nil {
		logrus.Errorf("Failed to attach tc ingress BPF to iface %s: %v", vethInfo.IfaceNameHost, err)
	}
	mountVxlanProc(vxlanl)

	// return
	// 本来我是想在清理函数中删除link的，但是考虑到iface index每次创建都会单调递增，下一次又创建感觉很浪费的样子，所以在测试阶段就别删了
	// lhost, _ := netlink.LinkByName(vethInfo.IfaceNameHost)
	return func() {
		if err := ns1.Close(); err != nil {
			logrus.Errorf("Failed to close ns1: %v", err)
		}
		// TODO: map清理
		// vxlanIfaceMap.Unpin()
		// vxlanIfaceMap.Close()
		// if err := netlink.LinkDel(lhost); err != nil {
		// 	logrus.Errorf("Failed to delete veth pair: %v", err)
		// }
	}, nil

}

func mountVxlanProc(vxlanl *netlink.Vxlan) error {
	// vxlan ebpf程序挂载
	// a. 先创建所需要的map，往里面填充对端信息
	dipVxlanMap := tc.MountMap("dipVxlan", "", 4096, tc.IPDstKey{}, tc.DIPVxlanValue{})
	// TODO: 每个测试节点需要填充的对端信息是不同的
	dst, _ := iptools.Ipv4Str2Uint32("10.244.1.0")
	dstNodeIp, _ := iptools.Ipv4Str2Uint32("10.176.40.187")
	err := dipVxlanMap.Put(
		tc.IPDstKey{Da: dst},
		tc.DIPVxlanValue{
			IfaceIndex: [8]uint32{uint32(vxlanl.Index)},
			VxlanIP:    [8]uint32{dstNodeIp},
		},
	)
	if err != nil {
		logrus.Errorf("Failed to put  DIPVxlanValue into map: %v", err)
		return err
	}

	// b. 挂载vxlan程序
	// 挂载egress程序
	_, err = tc.AttachTCVxlanEgressProg(vxlanl.Name) // 这里不考虑unmount了
	if err != nil {
		logrus.Errorf("Failed to attach vxlan egress BPF to iface %s: %v", vxlanl.Name, err)
		return err
	}
	// 挂载ingress程序
	_, err = tc.AttachTCVxlanIngressProg(vxlanl.Name)
	if err != nil {
		logrus.Errorf("Failed to attach vxlan ingress BPF to iface %s: %v", vxlanl.Name, err)
		return err
	}

	return nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		logrus.Warnf("Failed to load .env file: %v", err)
	} else {
		logrus.Infof("Loaded environment variables from .env file")
	}
	cleanupFunc, err := initNS(
		"ns3",                               // 命名空间
		"10.244.2.1",                        // 网关IP地址
		"/root/mulcni/pkg/ebpfProc/tc/tc.o", // tc ingress ebpf程序路径
	)
	if err != nil {
		logrus.Fatalf("[main] - Failed to init NS: %v", err)
	}

	defer cleanupFunc()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	<-stopCh
}
