package xdp

import (
	"net"

	"github.com/cilium/ebpf/link"
)

var (
	// Obj is the XDP program object
	//
	// 试图使用全局的Object，这样的话他们的Map就可以共享了吗？
	Obj *xdpObjects
)

func init() {
	Obj = &xdpObjects{}
	if err := loadXdpObjects(Obj, nil); err != nil {
		panic(err)
	}
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

func PutGatewayValue(key, value uint32) (bool, error) {
	err := Obj.xdpMaps.Gateway.Put(key, value)
	if err != nil {
		return false, err
	}
	return true, nil
}
