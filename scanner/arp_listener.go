package scanner

import (
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func listenForARPReplies(handle *pcap.Handle, timeout time.Duration) ([]Device, error) {
	var results []Device
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	timeoutChan := time.After(timeout)

	for {
		select {
		case packet := <-ps.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {

					ip := net.IP(arp.SourceProtAddress).String()
					mac := net.HardwareAddr(arp.SourceHwAddress).String()

					hostname := ""
					if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
						hostname = strings.TrimSuffix(names[0], ".")
					}

					vendor := lookupVendor(mac)

					results = append(results, Device{
						IP:       ip,
						MAC:      mac,
						Hostname: hostname,
						Vendor:   vendor,
					})
				}
			}
		case <-timeoutChan:
			return results, nil
		}
	}
}
