package arp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const (
	SysArpPath = "/proc/net/arp"
)

// GetMacForIpInCache looks up the ARP table for the given IP address and returns the corresponding MAC address.
// if the IP address is not found, it returns an error.
func GetMacForIpInCache(ip string) (net.HardwareAddr, error) {
	if f, err := os.Open(SysArpPath); err != nil {
		return nil, err
	} else {
		defer f.Close()
		var line string
		fileReader := bufio.NewReader(f)
		fileReader.ReadLine()
		for {
			line, err = fileReader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}
			fields := strings.Fields(line)
			if len(fields) != 6 {
				continue
			}
			if fields[0] == ip {
				mac, err := net.ParseMAC(fields[3])
				if err != nil {
					return nil, err
				}
				return mac, nil
			}
		}
		return nil, fmt.Errorf("IP %s not found in ARP table", ip)
	}
}
