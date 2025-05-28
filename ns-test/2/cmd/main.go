package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/SMALL-head/mulcni/pkg/ebpfProc/tc"
	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/SMALL-head/mulcni/utils/iptools"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/joho/godotenv"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"

	"github.com/sirupsen/logrus"
)

type IpSrcKey struct {
	sa uint32
}

type IpDstValue struct {
	da         uint32
	ifaceIndex uint32
	mac        [6]uint8
	padding    [2]uint8
}

func NewKeyValue(sa string, ifaceName string, macAddr []byte) (IpSrcKey, IpDstValue, error) {
	saUint32, _ := iptools.Ipv4Str2Uint32(sa)

	iface, err := net.InterfaceByName(ifaceName)

	if err != nil {
		return IpSrcKey{}, IpDstValue{}, err
	}
	IpSrcKey := IpSrcKey{sa: saUint32}
	IpDstValue := IpDstValue{da: saUint32, ifaceIndex: uint32(iface.Index), mac: ifacetools.TransferMacAddr(macAddr)}
	return IpSrcKey, IpDstValue, nil
}

func mountMap() *ebpf.Map {
	m := tc.MountMap("ip2Iface", "", 4096, IpSrcKey{}, IpDstValue{})
	// IpSrcKey := IpSrcKey{}
	// m.Put()
	return m
}

func main() {
	if err := godotenv.Load(); err != nil {
		logrus.Warnf("Failed to load .env file: %v", err)
	} else {
		logrus.Infof(".env file loaded successfully")
	}
	_, cancel := context.WithCancel(context.Background())

	ip2IfaceMap := mountMap()
	defer func() {
		ip2IfaceMap.Unpin()
		ip2IfaceMap.Close()
	}()

	// ns1, ns2 arp表项添加
	l, err := netlink.LinkByName("cic-host")
	if err != nil {
		logrus.Errorf("Failed to get link by name: %v", err)
	}
	addGatewayArp(l.Attrs().HardwareAddr, net.ParseIP("192.168.31.1"))

	//  向ip2IfaceMap中添加数据包的src和ifaceIndex,注意，mac地址是h-ns对端的mac地址
	k, v, _ := NewKeyValue("192.168.31.2", "h-ns1", []byte{0xbe, 0xcd, 0xcf, 0x48, 0xb3, 0x94})
	err = ip2IfaceMap.Put(k, v)
	if err != nil {
		logrus.Errorf("Failed to put value in map: %v", err)
	}
	k, v, _ = NewKeyValue("192.168.31.3", "h-ns2", []byte{0xaa, 0xea, 0x18, 0x87, 0xb1, 0x92})
	err = ip2IfaceMap.Put(k, v)
	if err != nil {
		logrus.Errorf("Failed to put value in map: %v", err)
	}

	hns1Iface := "h-ns1"
	unMount1, err := tc.AttachTCRedirectProg(hns1Iface)
	if err != nil {
		logrus.Errorf("Failed to attach TC redirect program to %s: %v", hns1Iface, err)
		return
	}
	defer unMount1()
	hns2Iface := "h-ns2"
	unMount2, err := tc.AttachTCRedirectProg(hns2Iface)
	if err != nil {
		logrus.Errorf("Failed to attach TC redirect program to %s: %v", hns2Iface, err)
		return
	}
	defer unMount2()

	// defer unMount()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt)
	<-stopCh
	cancel()

	time.Sleep(1 * time.Second)
}

func addGatewayArp(macAddr net.HardwareAddr, gatewayIp net.IP) {
	// 这里为ns1和ns2添加arp表项
	ns1, _ := ns.GetNS("/var/run/netns/ns1")
	ns2, _ := ns.GetNS("/var/run/netns/ns2")
	iptools.AddArpInNS(ns1, gatewayIp.String(), "v-ns1", macAddr)
	iptools.AddArpInNS(ns2, gatewayIp.String(), "v-ns2", macAddr)
}
