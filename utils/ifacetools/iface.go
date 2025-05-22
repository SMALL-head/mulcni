package ifacetools

import "net"

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
