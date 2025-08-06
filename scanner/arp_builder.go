package scanner

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildARPRequests(srcIP net.IP, srcMAC net.HardwareAddr, cidr string) ([][]byte, error) {
	var packets [][]byte

	ipNet, err := parseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		if ip.Equal(srcIP) {
			continue
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true}

		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		arp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(srcMAC),
			SourceProtAddress: []byte(srcIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(ip),
		}

		if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
			continue
		}

		packets = append(packets, buf.Bytes())
	}

	return packets, nil
} // ARPBuilder
