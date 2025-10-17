package protocoltools

import (
	"fmt"
	"net"
)

const (
	EthTypeIPv4 uint16 = 0x0800
)

type EthHeader [14]byte
type IpHeader [20]byte
type UdpHeader [8]byte
type VxlanHeader [8]byte

type MacAddr [6]byte

type IpAddr [4]byte

func (m MacAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// getSrc 获取[0:6]字节，为目的地址
func (e EthHeader) getDst() (addr MacAddr) {
	addr = MacAddr(e[0:6])
	return
}

func (e EthHeader) getSrc() (addr MacAddr) {
	addr = MacAddr(e[6:12])
	return
}

func (e EthHeader) getEthType() uint16 {
	return uint16(e[12])<<8 + uint16(e[13])
}

// getVersion 获取IP版本，[0:4]
func (iph IpHeader) getVersion() string {
	switch iph[0] >> 4 {
	case 4:
		return "IPv4"
	case 6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

func (i IpAddr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", i[0], i[1], i[2], i[3])
}

func (u UdpHeader) getSrcPort() int {
	return int(u[0])<<8 + int(u[1])
}

func (u UdpHeader) getDstPort() int {
	return int(u[2])<<8 + int(u[3])
}

func (u UdpHeader) getLen() int {
	return int(u[4])<<8 + int(u[5])
}

// getIphLen 获取IP头长度，单位字节。[4:8]
func (iph IpHeader) getIphLen() int {
	return int((iph[0] & 0x0F) * 4)
}

// getTos 获取服务类型，[8:16]
func (iph IpHeader) getTos() int {
	return int(iph[1])
}

// getTotalLen 获取总长度，[16:32]
// 封装的时候，这个值需要重新计算(20(ip) + 8(udp) + 8(vxlan) + inner total len(eth, skb->len直接获取即可))
func (iph IpHeader) getTotalLen() int {
	return int(iph[2])<<8 + int(iph[3])
}

// 其他东西我不关心了，只关心src和dst

func (iph IpHeader) getSrcIp() IpAddr {
	return IpAddr(iph[12:16])
}

func (iph IpHeader) getDstIp() IpAddr {
	return IpAddr(iph[16:20])
}

func (v VxlanHeader) getVNI() int {
	return int(v[4])<<16 + int(v[5])<<8 + int(v[6])
}

func parseValue(raw [50]byte) (EthHeader, IpHeader, UdpHeader, VxlanHeader) {
	return EthHeader(raw[0:14]), IpHeader(raw[14:34]), UdpHeader(raw[34:42]), VxlanHeader(raw[42:50])
}

func constructEthHeader(ethDst, ethSrc string, ethType uint16) (EthHeader, error) {
	eDstSlice, err := net.ParseMAC(ethDst)
	if err != nil {
		return EthHeader{}, err
	}
	eSrcSlice, err := net.ParseMAC(ethSrc)
	if err != nil {
		return EthHeader{}, err
	}
	var eth EthHeader
	copy(eth[0:6], eDstSlice)
	copy(eth[6:12], eSrcSlice)
	eth[12] = byte(ethType >> 8)
	eth[13] = byte(ethType & 0xFF)
	return eth, nil
}

func constructIpv4Header(ipSrc, ipDst string) (IpHeader, error) {
	sip := net.ParseIP(ipSrc).To4()
	if sip == nil {
		return IpHeader{}, fmt.Errorf("invalid ip src %s", ipSrc)
	}
	dip := net.ParseIP(ipDst).To4()
	if dip == nil {
		return IpHeader{}, fmt.Errorf("invalid ip dst %s", ipDst)
	}
	var iph IpHeader
	iph[0] = 0x45
	iph[1] = 0x00
	// total len, need to calculate later
	// iph[2] = ?
	// iph[3] = ?
	iph[4] = 0x11 // identification
	iph[5] = 0xe6
	iph[6] = 0x00 // flags(3 bits) + fragment offset(13 bits)
	iph[7] = 0x00
	iph[8] = 64    // ttl
	iph[9] = 17    // protocol, udp=17
	iph[10] = 0x01 // header checksum, need to calculate later
	iph[11] = 0xab
	copy(iph[12:16], sip)
	copy(iph[16:20], dip)

	// calculate checksum
	iph[10] = 0x00
	iph[11] = 0x00
	checksum := checksumForIpv4Header(&iph)
	iph[10] = byte(checksum >> 8)
	iph[11] = byte(checksum & 0xFF)

	return iph, nil
}

func checksumForIpv4Header(iph *IpHeader) uint16 {
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(iph[i])<<8 + uint32(iph[i+1])
	}
	// add carry bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	// one's complement
	return uint16(^sum)
}

func constructUdpHeader(srcPort, dstPort int) (UdpHeader, error) {
	var udph UdpHeader
	udph[0] = byte(srcPort >> 8)
	udph[1] = byte(srcPort & 0xFF)
	udph[2] = byte(dstPort >> 8)
	udph[3] = byte(dstPort & 0xFF)
	// length, need to calculate later
	// udph[4] = ?
	// udph[5] = ?
	udph[6] = 0x00 // checksum, optional for UDP, set to 0
	udph[7] = 0x00
	return udph, nil
}

func constructVxlanHeader(vni int) (VxlanHeader, error) {
	var vxlanh VxlanHeader
	vxlanh[0] = 0x08 // flags, I flag set
	vxlanh[1] = 0x00
	vxlanh[2] = 0x00
	vxlanh[3] = 0x00
	vxlanh[4] = byte((vni >> 16) & 0xFF)
	vxlanh[5] = byte((vni >> 8) & 0xFF)
	vxlanh[6] = byte(vni & 0xFF)
	vxlanh[7] = 0x00 // reserved
	return vxlanh, nil
}

func ConstructRaw(ethDst string, ethSrc string, ipSrc, ipDst string, udpSrcPort, udpDstPort int, vni int) ([50]byte, error) {
	var res []byte

	// eth header
	eth, err := constructEthHeader(ethDst, ethSrc, EthTypeIPv4)
	if err != nil {
		return [50]byte{}, err
	}
	res = append(res, eth[:]...)

	// ip header

	iph, err := constructIpv4Header(ipSrc, ipDst)
	if err != nil {
		return [50]byte{}, err
	}
	res = append(res, iph[:]...)

	// udp header
	udph, err := constructUdpHeader(udpSrcPort, udpDstPort)
	if err != nil {
		return [50]byte{}, err
	}
	res = append(res, udph[:]...)

	// vxlan header
	vxlanh, err := constructVxlanHeader(vni)
	if err != nil {
		return [50]byte{}, err
	}
	res = append(res, vxlanh[:]...)

	var raw [50]byte
	copy(raw[:], res)
	return raw, nil
}
