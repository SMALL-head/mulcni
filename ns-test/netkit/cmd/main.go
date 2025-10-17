package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/SMALL-head/mulcni/pkg/ebpfProc/tc"
	"github.com/SMALL-head/mulcni/utils/arp"
	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/SMALL-head/mulcni/utils/iptools"
	_ "github.com/SMALL-head/mulcni/utils/log"
	"github.com/SMALL-head/mulcni/utils/protocoltools"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/joho/godotenv"

	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetReportCaller(true)
	if err := godotenv.Load(); err != nil {
		logrus.Fatalf("failed to load .env file: %v", err)
	}

	ns1Name := os.Getenv("NS1")
	gatewayIP1 := os.Getenv("GATEWAY_IP1")
	gatewayIP2 := os.Getenv("GATEWAY_IP2")
	veth1IP := os.Getenv("VETH1_IP")
	veth2IP := os.Getenv("VETH2_IP")
	VXLAN_DST_IP1 := os.Getenv("VXLAN_DST_IP1")
	VXLAN_DST_IP2 := os.Getenv("VXLAN_DST_IP2")
	unMountTCProgs, err := attachTCProg()
	defer unMountTCProgs()
	if err != nil {
		logrus.Fatalf("Failed to attach TC programs: %v", err)
	}

	cleanup, err := initNS(ns1Name, gatewayIP1, gatewayIP2, veth1IP, veth2IP)
	if err != nil {
		logrus.Fatalf("Failed to init ns: %v", err)
	}

	// vxlan首部信息封装
	vxlanHeaderMapInit([]string{VXLAN_DST_IP1, VXLAN_DST_IP2}, []string{"eno8303", "eno8403"})
	defer cleanup()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	<-stopCh
}

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

	dipVxlanMap := tc.MountMap("dipVxlan", "", 4096, tc.IPDstKey{}, tc.DIPVxlanValue{})
	// TODO: 每个测试节点需要填充的对端信息是不同的
	// dst, _ := iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_NS_IP1"))
	// dstNodeIp1, _ := iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_IP1"))
	// dstNodeIp2, _ := iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_IP2"))
	// lbFactor := uint16(0)
	// // 高8位设置有效数量
	// lbFactor |= (2 << 8)
	// err = dipVxlanMap.Put(
	// 	tc.IPDstKey{Da: dst},
	// 	tc.DIPVxlanValue{
	// 		IfaceIndex: [8]uint32{uint32(0), uint32(0)},
	// 		VxlanIP:    [8]uint32{dstNodeIp1, dstNodeIp2},
	// 		LBFactor:   lbFactor,
	// 	},
	// )
	// if err != nil {
	// 	logrus.Errorf("Failed to put  DIPVxlanValue into map: %v", err)
	// 	return nil, err
	// }

	dst, _ := iptools.Ipv4Str2Uint32(os.Getenv("DST_IP"))
	dstNodeIp1, _ := iptools.Ipv4Str2Uint32(os.Getenv("VXLAN_DST_IP1"))
	lbFactor := uint16(0)

	// 寻找dstNodeIp1这个网段对应的本机的iface的编号
	if dstNodeIp1 == 0 {
		logrus.Fatalf("Unabled to find dstNodeIp1 from env")
	}

	dstNodeIp1Iface, err := iptools.GetInterfaceByDstIP(os.Getenv("VXLAN_DST_IP1"))
	if err != nil {
		logrus.Fatalf("Failed to get iface by ipaddr %s: %v", os.Getenv("VXLAN_DST_IP1"), err)
	}

	// 高8位设置有效数量
	lbFactor |= (1 << 8)
	err = dipVxlanMap.Put(
		tc.IPDstKey{Da: dst},
		tc.DIPVxlanValue{
			IfaceIndex: [8]uint32{uint32(dstNodeIp1Iface.Index)},
			VxlanIP:    [8]uint32{dstNodeIp1},
			LBFactor:   lbFactor,
		},
	)
	if err != nil {
		logrus.Errorf("Failed to put  DIPVxlanValue into map: %v", err)
		return nil, err
	}

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

	return func() {}, nil
}

func vxlanHeaderMapInit(dstIPStrs []string, localInterface []string) error {
	// key: iface序号，value：ip地址和mac地址
	ifaceMacMap := tc.MountMap("ifaceMacMap", "", 4096, uint32(0), tc.IfaceMac{})
	for _, ifaceName := range localInterface {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			logrus.Errorf("Failed to get iface %s: %v", ifaceName, err)
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			logrus.Errorf("Failed to get addrs for iface %s: %v", ifaceName, err)
			continue
		}
		addrStr := addrs[0].String()
		ipAddr, _, err := net.ParseCIDR(addrStr)
		if err != nil {
			logrus.Errorf("Failed to parse ip addr %s: %v", addrStr, err)
			continue
		}
		ipUin32, err := iptools.Ip2Uint32(ipAddr)
		if err != nil {
			logrus.Errorf("Failed to parse ip %s: %v", ipAddr.String(), err)
			continue
		}
		if err = ifaceMacMap.Put(uint32(iface.Index),
			tc.IfaceMac{
				Mac:    [6]uint8(iface.HardwareAddr),
				Ipaddr: ipUin32,
			}); err != nil {
			logrus.Errorf("Failed to put ifaceMac into map: %v", err)
		}
	}

	// key: 目的ip段，value：vxlan首部
	vxlanHeaderMap := tc.MountMap("vxlanHeaderMap", "", 128, tc.IPDstKey{}, tc.VxlanHeader{})
	for _, ipStr := range dstIPStrs { // 宿主机的ip
		ethDst, err := arp.GetMacForIpInCache(ipStr)
		if err != nil {
			logrus.Errorf("Failed to get mac for ip %s in arp cache: %v", ipStr, err)
			continue
		}

		da, err := iptools.Ipv4Str2Uint32(ipStr)
		if err != nil {
			logrus.Errorf("Failed to parse ip %s: %v", ipStr, err)
			continue
		}

		hd, err := protocoltools.ConstructRaw(ethDst.String(), "00:00:00:00:00:00", "0.0.0.0", ipStr, 45042, 8472, 13001)
		if err != nil {
			logrus.Errorf("Failed to construct vxlan header for ip %s: %v", ipStr, err)
			continue
		}

		if err = vxlanHeaderMap.Put(
			tc.IPDstKey{Da: da},
			tc.VxlanHeader{Header: hd},
		); err != nil {
			logrus.Errorf("Failed to put vxlan header into map for ip %s: %v", ipStr, err)
		}
	}

	return nil
}

// 对宿主机网卡上挂载vxlan解包程序，为veth pair的宿主机端口侧挂载vxlan封装程序。该场景下直接通过vxlan封包
func attachTCProg() (cleanup func(), err error) {
	var cleanups []func() error

	cleanup = func() {
		for _, unMount := range cleanups {
			if err_ := unMount(); err_ != nil {
				logrus.Errorf("Failed to unmount tc program: %v", err_)
			}
		}
	}

	unMountFunc, err := tc.AttachTCIngressProgWithSec("eno8303", "classifier/redirect_directly")
	if err != nil {
		logrus.Errorf("Failed to attach TC program: %v", err)
		return nil, err
	}
	cleanups = append(cleanups, unMountFunc)

	unMountForHostVeth, err := tc.AttachTCIngressProgWithSec("h-ns11", "classifier/vxlan")
	if err != nil {
		logrus.Errorf("Faile to attach TC(classifier/vxlan) program to h-ns11: %v", err)
		return cleanup, err
	}
	cleanups = append(cleanups, unMountForHostVeth)

	return cleanup, nil
}
