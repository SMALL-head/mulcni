package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/SMALL-head/mulcni/pkg/ebpfProc/tc"
	"github.com/SMALL-head/mulcni/pkg/ebpfProc/xdp"
	"github.com/SMALL-head/mulcni/utils/ifacetools"
	"github.com/SMALL-head/mulcni/utils/iptools"

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

func loadXDP(ctx context.Context, ifaceName string) error {
	l, err := xdp.LoadXdpProg(ifaceName)
	if err != nil {
		logrus.Errorf("Failed to load XDP program: %v", err)
		return err
	}
	defer func() {
		l.Close()
		xdp.Obj.Close()
		logrus.Printf("offloaded all XDP programs on iface: %s", ifaceName)
	}()

	for range ctx.Done() {
		logrus.Printf("🔴 Stopping XDP program on iface: %s...", "h-ns1")
		return nil
	}
	return nil
}

func main() {

	_, cancel := context.WithCancel(context.Background())
	// 1. 向xdpMap中添加cic-host的index，这样的话h-xx网卡才能够redirect到cic-host
	// iface, err := net.InterfaceByName("cic-host")
	// if err != nil {
	// 	logrus.Errorf("Failed to get interface cic-host: %v", err)
	// 	return
	// }
	// defer xdp.Obj.Close() // 全局load后应该关闭
	// _, err = xdp.PutGatewayValue(0, uint32(iface.Index))
	// if err != nil {
	// 	logrus.Errorf("Failed to put value in XDP map: %v", err)
	// 	return
	// }

	// 2. 为h-xx的网卡挂载xdp，这些xdp会将数据包重定向到cic-host
	// go loadXDP(ctx, "h-ns1")
	// go loadXDP(ctx, "h-ns2")

	ip2IfaceMap := mountMap()
	defer func() {
		ip2IfaceMap.Unpin()
		ip2IfaceMap.Close()
	}()

	// 2.1 向ip2IfaceMap中添加数据包的src和ifaceIndex,注意，mac地址是h-ns对端的mac地址
	k, v, _ := NewKeyValue("192.168.31.2", "h-ns1", []byte{0xbe, 0xcd, 0xcf, 0x48, 0xb3, 0x94})
	err := ip2IfaceMap.Put(k, v)
	if err != nil {
		logrus.Errorf("Failed to put value in map: %v", err)
	}
	k, v, _ = NewKeyValue("192.168.31.3", "h-ns2", []byte{0xaa, 0xea, 0x18, 0x87, 0xb1, 0x92})
	err = ip2IfaceMap.Put(k, v)
	if err != nil {
		logrus.Errorf("Failed to put value in map: %v", err)
	}

	// 3. 为cic-host挂载tc程序，tc程序会查找ip2IfaceMap中的信息，将数据包再次重定向到指定的网卡上
	// cicHostIface := "cic-host"
	// unMount, err := tc.AttachTCRedirectProg(cicHostIface)
	// if err != nil {
	// 	logrus.Errorf("Failed to attach TC redirect program to %s: %v", cicHostIface, err)
	// 	return
	// }

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
