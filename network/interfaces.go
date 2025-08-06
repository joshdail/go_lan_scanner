package network

import (
	"fmt"
	"net"
)

type NetworkInfo struct {
	InterfaceName string
	IP            net.IP
	CIDR          string
}

func GetDefaultInterface() (*NetworkInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if !isUsable(iface) {
			continue
		}

		ip, cidr, err := getFirstIPv4Addr(&iface)

		if err == nil {
			return &NetworkInfo{
				InterfaceName: iface.Name,
				IP:            ip,
				CIDR:          cidr,
			}, nil
		}
	}
	// If no interface found, return error
	return nil, fmt.Errorf("no usable network interface found")
} // GetDefaultInterface

// Checks if interface is up and is not a loopback
func isUsable(iface net.Interface) bool {
	return iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0
} // isUsable

// Finds the first IPv4 address + CIDR on a given interface
func getFirstIPv4Addr(iface *net.Interface) (net.IP, string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, "", err
	}
	// Loop through and return an interface if found
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP, ipnet.String(), nil
	}
	// Return if no IP address found
	return nil, "", fmt.Errorf("no IPv4 address found on %s", iface.Name)
} // getFirstIPv4Addr
