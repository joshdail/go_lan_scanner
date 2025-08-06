package scanner

import (
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

func ARPScan(ifaceName string, cidr string) ([]Device, error) {
	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open device: %w", err)
	}
	defer handle.Close()

	srcIP, srcMAC, err := getInterfaceIPAndMAC(ifaceName)
	if err != nil {
		return nil, err
	}

	packets, err := buildARPRequests(srcIP, srcMAC, cidr)
	if err != nil {
		return nil, err
	}

	if err := sendARPRequests(handle, packets); err != nil {
		return nil, err
	}

	return listenForARPReplies(handle, 2*time.Second)
} // ARPScan
