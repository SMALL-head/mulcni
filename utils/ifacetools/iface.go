package ifacetools

import (
	"errors"
	"net"
	"os/exec"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func execCmd(cmd string) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type VethPairInfo struct {
	IfaceNameHost string
	IfaceNameNs   string
	LinkIndexHost int
	LinkIndexNs   int
	IfaceIp       *net.IPNet
	IfaceHostAddr net.HardwareAddr
	IfaceNsAddr   net.HardwareAddr
}

func GetIfaceIdx(ifaceName string) (int, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return -1, err
	}
	return iface.Index, nil
}

func TransferMacAddr(hwAddr net.HardwareAddr) [6]uint8 {
	var mac [6]uint8
	for i := 0; i < 6; i++ {
		mac[i] = hwAddr[i]
	}
	return mac
}

// CreateVethPair 创建一对veth pair
func CreateVethPair(v1, v2 string) (*netlink.Veth, *netlink.Veth, error) {
	// 先看有没有存在同名的veth pair，如果存在则返回
	l1, _ := netlink.LinkByName(v1)
	l2, _ := netlink.LinkByName(v2)
	if l1 != nil && l2 != nil {
		veth1, ok1 := l1.(*netlink.Veth)
		veth2, ok2 := l2.(*netlink.Veth)
		if !ok1 || !ok2 {
			return nil, nil, errors.New("存在同名veth但是不是veth类型")
		}
		return veth1, veth2, nil
	} else if l1 != nil || l2 != nil {
		// 如果只有一个存在，这种情况抛给上层解决，本方法不做处理
		return nil, nil, errors.New("存在同名veth但是只有一个存在, 请自行删除")
	}

	vethPair := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: v1,
			MTU:  1500,
		},
		PeerName: v2,
	}

	if err := netlink.LinkAdd(vethPair); err != nil {
		return nil, nil, err
	}

	l1, err := netlink.LinkByName(v1)
	if err != nil {
		return nil, nil, err
	}
	l2, err = netlink.LinkByName(v2)
	if err != nil {
		return nil, nil, err
	}

	return l1.(*netlink.Veth), l2.(*netlink.Veth), nil
}

// 该函数创建一对veth pair，其中ifaceNameHost为主机端的veth接口名称，ifaceNameNs为命名空间中的veth接口名称
// 该函数在创建接口后会将名为ifaceNameNs的接口移动到nsPath指定的命名空间中，并且配置ip地址
// ipAddr类似为"10.244.0.0/16"
// 最终该函数会返回有关这对veht pair的相关信息
func CreateVethInNs(nsPath string, ifaceNameHost, ifaceNameNs string, ipAddr string) (*VethPairInfo, error) {
	n, err := ns.GetNS(nsPath)
	if err != nil {
		return nil, err
	}

	res := VethPairInfo{}

	err = n.Do(func(hostNs ns.NetNS) error {
		l, _ := netlink.LinkByName(ifaceNameNs)
		nsVeth, ok := l.(*netlink.Veth)
		if ok && nsVeth != nil {
			err2 := hostNs.Do(func(_ ns.NetNS) error {
				l, err := netlink.LinkByName(ifaceNameHost)
				if err != nil {
					return err
				}
				hostVeth, ok := l.(*netlink.Veth)
				if !ok {
					return errors.New("host veth is not a Veth type")
				}
				ipaddr, ipnet, err := net.ParseCIDR(ipAddr)
				if err != nil {
					return err
				}
				ipnet.IP = ipaddr
				// 如果ns中的veth已经存在，则直接返回
				res.IfaceNameHost = ifaceNameHost
				res.IfaceNameNs = ifaceNameNs
				res.IfaceIp = ipnet
				res.IfaceHostAddr = hostVeth.HardwareAddr
				res.IfaceNsAddr = nsVeth.HardwareAddr
				res.LinkIndexHost = hostVeth.Index
				res.LinkIndexNs = nsVeth.Index
				return nil
			})
			if err2 != nil {
				return err2
			}
			return nil
		}
		// 从ns中创建veth pair
		nsVeth, hostVeth, err := CreateVethPair(ifaceNameNs, ifaceNameHost)
		if err != nil {
			return err
		}
		// 解析并赋值ip地址给namespace中的veth接口
		ipaddr, ipnet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			return err
		}
		ipnet.IP = ipaddr
		err = netlink.AddrAdd(nsVeth, &netlink.Addr{IPNet: ipnet})
		if err != nil {
			return err
		}

		// 主机侧veth装配
		if err = netlink.LinkSetNsFd(hostVeth, int(hostNs.Fd())); err != nil {
			return err
		}

		// 将namespace和host上的veth接口都设置为up状态
		netlink.LinkSetUp(nsVeth)
		// 顺便把lo设备也开启
		loDevice, err := netlink.LinkByName("lo")
		if err != nil {
			logrus.Warnf("failed to get lo device: %v", err)
		} else {
			err = netlink.LinkSetUp(loDevice)
			if err != nil {
				logrus.Warnf("failed to set lo device up: %v", err)
			}
		}
		var hostVethIdx int
		if err = hostNs.Do(func(_ ns.NetNS) error {
			l, err := netlink.LinkByName(hostVeth.Name)
			if err != nil {
				return err
			}
			hostVethIdx = l.Attrs().Index
			return netlink.LinkSetUp(l)
		}); err != nil {
			logrus.Errorf("failed to set host veth up: %v", err)
		}

		// 封装返回值
		res.IfaceNameHost = ifaceNameHost
		res.IfaceNameNs = ifaceNameNs
		res.IfaceIp = ipnet
		res.IfaceHostAddr = hostVeth.HardwareAddr
		res.IfaceNsAddr = nsVeth.HardwareAddr
		res.LinkIndexHost = hostVethIdx
		res.LinkIndexNs = nsVeth.Index
		return nil
	})

	return &res, err
}

func CreateVxlanAndUp(vxlanName string) (*netlink.Vxlan, error) {
	l, _ := netlink.LinkByName(vxlanName)
	vxlanl, ok := l.(*netlink.Vxlan)
	if ok && vxlanl != nil {
		netlink.LinkSetUp(vxlanl)
		logrus.Infof("vxlan %s already exists", vxlanName)
		return vxlanl, nil
	}
	_, err := execCmd("ip link add name " + vxlanName + " type vxlan external")
	if err != nil {
		logrus.Errorf("failed to create vxlan %s: %v", vxlanName, err)
		return nil, err
	}
	l, err = netlink.LinkByName(vxlanName)
	if err != nil {
		logrus.Errorf("failed to get vxlan %s: %v", vxlanName, err)
		return nil, err
	}
	vxlanl = l.(*netlink.Vxlan)
	netlink.LinkSetUp(vxlanl)
	return vxlanl, nil
}
