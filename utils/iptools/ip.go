package iptools

import (
	"encoding/binary"
	"fmt"
	"net"
)

func Ipv4Str2Uint32(ipv4Str string) (uint32, error) {
	ip := net.ParseIP(ipv4Str)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipv4Str)
	}
	res := binary.BigEndian.Uint32(ip.To4())
	return res, nil
}
