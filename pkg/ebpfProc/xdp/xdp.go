package xdp

import (
	"net"
	"reflect"

	"github.com/SMALL-head/mulcni/utils/iptools"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

var (
	// Obj is the XDP program object
	//
	// 试图使用全局的Object，这样的话他们的Map就可以共享了吗？map手动pin
	Obj *xdpObjects
)

func init() {
	_ = MountHashMap("gateway", "", 8, uint32(0), uint32(0))

	Obj = &xdpObjects{}
	if err := loadXdpObjects(Obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/xdp/globals/",
		},
	}); err != nil {
		panic(err)
	}
}

func PutIp2Iface(da net.IP, ifaceIndex uint32, macAddr [6]byte) (bool, error) {
	daIP, err := iptools.Ip2Uint32(da)
	if err != nil {
		return false, err
	}
	k := xdpIpDstKey{
		Da: daIP,
	}

	v := xdpIpDstValue{
		Da:         daIP,
		IfaceIndex: ifaceIndex,
		Mac:        macAddr,
	}

	err = Obj.Ip2Iface.Put(&k, &v)
	if err != nil {
		return false, err
	}
	return true, nil
}

func PutDipVxlan(da uint32, ifaceIndex []uint32, nodesIP []uint32) error {
	k := xdpIpDstKey{
		Da: da,
	}
	var ifaceIdxArr [8]uint32
	var vxlanIPsArr [8]uint32

	if len(ifaceIndex) > len(ifaceIdxArr) {
		ifaceIndex = ifaceIndex[:len(ifaceIdxArr)]
	}
	if len(nodesIP) > len(vxlanIPsArr) {
		nodesIP = nodesIP[:len(vxlanIPsArr)]
	}

	copy(ifaceIdxArr[:], ifaceIndex)
	copy(vxlanIPsArr[:], nodesIP)

	v := xdpDipVxlanValue{
		IfaceIndex: ifaceIdxArr, // 记录vxlan包转发的宿主机网卡
		VxlanIP:    vxlanIPsArr, // 记录vxlan包的目的ip
		LbFactor:   uint16(len(nodesIP))<<8 | uint16(0),
	}
	return Obj.DipVxlan.Put(&k, &v)
}

func LoadXdpProg(ifaceName string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	ifaceIdx := iface.Index
	// Attach the XDP program to the interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   Obj.XdpRedirectGateway,
		Interface: ifaceIdx,
	})

	if err != nil {
		return nil, err
	}
	return l, nil
}

func LoadXDPVxlanProg(ifaceName string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	ifaceIdx := iface.Index
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   Obj.XdpStripVxlanRedirect,
		Interface: ifaceIdx,
	})

	if err != nil {
		return nil, err
	}

	return l, nil
}

func PutGatewayValue(key, value uint32) (bool, error) {
	err := Obj.xdpMaps.Gateway.Put(key, value)
	if err != nil {
		return false, err
	}
	return true, nil
}

func MountHashMap(mapName string, pinPath string, maxEntries uint32, key, value any) *ebpf.Map {
	if pinPath == "" {
		pinPath = "/sys/fs/bpf/xdp/globals/"
	}
	keySize, valueSize := uint32(reflect.TypeOf(key).Size()), uint32(reflect.TypeOf(value).Size())

	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       mapName,
		Pinning:    ebpf.PinByName, // 自动pin了
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		logrus.Fatalf("Failed to create map: %v", err)
	}

	return m
}
