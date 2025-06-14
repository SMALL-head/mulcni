package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/SMALL-head/mulcni/pkg/ebpfProc/tc"
	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/SMALL-head/mulcni/utils/iptools"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// gatewayIPStr 是网关的IP地址,不带掩码位
func initNS(nsName string, gateWayIPStr1, gateWayIPStr2 string, veth1IPStr, veth2IPStr string) (cleanup func(), err error) {
	ns1, err := ns.GetNS(fmt.Sprintf("/var/run/netns/%s", nsName))
	if err != nil {
		logrus.Errorf("Failed to get %s: %v", nsName, err)
		return nil, err
	}

	vethInfo1, err := ifacetools.CreateVethInNs(
		fmt.Sprintf("/var/run/netns/%s", nsName),
		fmt.Sprintf("h-%s%d", nsName, 1),
		fmt.Sprintf("v-%s%d", nsName, 1),
		veth1IPStr,
	)
	if err != nil {
		if err.Error() == "file exists" {
			logrus.Infof("veth pair \"%s\"<->\"%s\" already exists", vethInfo1.IfaceNameHost, vethInfo1.IfaceNameNs)
		} else {
			logrus.Fatalf("Failed to create veth pair in ns: %v", err)
		}
	}

	vethInfo2, err := ifacetools.CreateVethInNs(
		fmt.Sprintf("/var/run/netns/%s", nsName),
		fmt.Sprintf("h-%s%d", nsName, 2),
		fmt.Sprintf("v-%s%d", nsName, 2),
		veth2IPStr,
	)
	if err != nil {
		if err.Error() == "file exists" {
			logrus.Infof("veth pair \"%s\"<->\"%s\" already exists", vethInfo2.IfaceNameHost, vethInfo2.IfaceNameNs)
		} else {
			logrus.Fatalf("Failed to create veth pair in ns: %v", err)
		}
	}

	// 在ip2Iface中添加对应的表项
	ip2IfaceMap := tc.MountMap("ip2Iface", "", 4096, tc.IPDstKey{}, tc.IPDstValue{})
	da, _ := iptools.Ip2Uint32(vethInfo1.IfaceIp.IP)
	if err = ip2IfaceMap.Put(
		tc.IPDstKey{Da: da},
		tc.IPDstValue{
			Da:         da,
			IfaceIndex: uint32(vethInfo1.LinkIndexHost),
			Mac:        [6]uint8(vethInfo1.IfaceNsAddr),
		},
	); err != nil {
		logrus.Errorf("Failed to put IPDstValue into ip2Iface map: %v", err)
	}
	da, _ = iptools.Ip2Uint32(vethInfo2.IfaceIp.IP)
	if err = ip2IfaceMap.Put(
		tc.IPDstKey{Da: da},
		tc.IPDstValue{
			Da:         da,
			IfaceIndex: uint32(vethInfo2.LinkIndexHost),
			Mac:        [6]uint8(vethInfo2.IfaceNsAddr),
		},
	); err != nil {
		logrus.Errorf("Failed to put IPDstValue into ip2Iface map: %v", err)
	}

	// host主机中的veth pair
	// cicHost1, cicHostPeer1, err := ifacetools.CreateVethPair("cic-host1", "cic-host-peer1")
	// if err != nil {
	// 	if err.Error() == "file exists" {
	// 		logrus.Infof("veth pair \"cic-host1\"<->\"cic-host-peer1\" already exists")
	// 	} else {
	// 		logrus.Fatalf("Failed to create host gateway veth pair: %v", err)
	// 	}
	// }
	// gatewayIP1, gatewayIpNet1, _ := net.ParseCIDR(fmt.Sprintf("%s/24", gateWayIPStr1))
	// gatewayIpNet1.IP = gatewayIP1
	// netlink.AddrAdd(cicHost1, &netlink.Addr{IPNet: gatewayIpNet1})
	// netlink.LinkSetUp(cicHost1)
	// netlink.LinkSetUp(cicHostPeer1)

	// arp 表项添加
	err = iptools.AddArpInNS(ns1, gateWayIPStr1, vethInfo1.IfaceNameNs, vethInfo1.IfaceHostAddr)
	if err != nil {
		logrus.Errorf("Failed to add ARP entry in ns: %v", err)
		return nil, err
	}
	err = iptools.AddArpInNS(ns1, gateWayIPStr2, vethInfo2.IfaceNameNs, vethInfo2.IfaceHostAddr)
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
	cleanUpHostIngress1, err := tc.AttachTCRedirectProg(vethInfo1.IfaceNameHost)
	if err != nil {
		logrus.Errorf("Failed to attach tc ingress BPF to iface %s: %v", vethInfo1.IfaceNameHost, err)
	}
	cleanUpHostIngress2, err := tc.AttachTCRedirectProg(vethInfo2.IfaceNameHost)
	if err != nil {
		logrus.Errorf("Failed to attach tc ingress BPF to iface %s: %v", vethInfo2.IfaceNameHost, err)
	}

	cleanUpVxlanEIngress, err := mountVxlanProc(vxlanl)
	if err != nil {
		logrus.Errorf("Failed to mount vxlan ingress BPF: %v", err)
	}

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
		cleanUpHostIngress1()
		cleanUpHostIngress2()
		cleanUpVxlanEIngress()
	}, nil

}

// return 清理函数，该清理函数用于清除vxlan设备上挂载的ingress 和 egress tc程序
func mountVxlanProc(vxlanl *netlink.Vxlan) (func(), error) {
	// vxlan ebpf程序挂载
	// a. 先创建所需要的map，往里面填充对端信息
	dipVxlanMap := tc.MountMap("dipVxlan", "", 4096, tc.IPDstKey{}, tc.DIPVxlanValue{})
	// TODO: 每个测试节点需要填充的对端信息是不同的
	dst, _ := iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_NS_IP1"))
	dstNodeIp, _ := iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_IP1"))
	err := dipVxlanMap.Put(
		tc.IPDstKey{Da: dst},
		tc.DIPVxlanValue{
			IfaceIndex: [8]uint32{uint32(vxlanl.Index)},
			VxlanIP:    [8]uint32{dstNodeIp},
		},
	)
	if err != nil {
		logrus.Errorf("Failed to put  DIPVxlanValue into map: %v", err)
		return nil, err
	}
	dst, _ = iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_NS_IP2"))
	err = dipVxlanMap.Put(
		tc.IPDstKey{Da: dst},
		tc.DIPVxlanValue{
			IfaceIndex: [8]uint32{uint32(vxlanl.Index)},
			VxlanIP:    [8]uint32{dstNodeIp},
		},
	)
	if err != nil {
		logrus.Errorf("Failed to put  DIPVxlanValue into map: %v", err)
		return nil, err
	}

	// b. 挂载vxlan程序
	// 挂载egress程序
	cleanUpEgress, err := tc.AttachTCVxlanEgressProg(vxlanl.Name) // 这里不考虑unmount了
	if err != nil {
		logrus.Errorf("Failed to attach vxlan egress BPF to iface %s: %v", vxlanl.Name, err)
		return nil, err
	}
	// 挂载ingress程序
	cleanUpIngress, err := tc.AttachTCVxlanIngressProg(vxlanl.Name)
	if err != nil {
		logrus.Errorf("Failed to attach vxlan ingress BPF to iface %s: %v", vxlanl.Name, err)
		return func() {
			cleanUpEgress()
		}, err
	}

	return func() {
		cleanUpEgress()
		cleanUpIngress()

	}, nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		logrus.Warnf("Failed to load .env file: %v", err)
	} else {
		logrus.Infof("Loaded environment variables from .env file")
	}
	ns1Name := os.Getenv("NS1")
	gatewayIP1 := os.Getenv("GATEWAY_IP1")
	gatewayIP2 := os.Getenv("GATEWAY_IP2")
	veth1IP := os.Getenv("VETH1_IP")
	veth2IP := os.Getenv("VETH2_IP")
	cleanupFunc, err := initNS(
		ns1Name,    // 命名空间
		gatewayIP1, // 网关IP地址
		gatewayIP2, // 另一个网关IP地址
		veth1IP,    // veth1的IP地址
		veth2IP,    // veth2的IP地址
	)
	if err != nil {
		logrus.Fatalf("[main] - Failed to init NS: %v", err)
	}

	defer cleanupFunc()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	<-stopCh
}
