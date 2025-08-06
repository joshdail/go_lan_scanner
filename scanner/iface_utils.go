package scanner

import (
	"fmt"
	"net"
)

func getInterfaceIPAndMAC(name string) (net.IP, net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ip := ipNet.IP.To4()
			if ip != nil {
				return ip, iface.HardwareAddr, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no IPv4 address found for interface %s", name)
} // getInterfaceIPAndMAC
