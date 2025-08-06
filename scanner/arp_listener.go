package scanner

import (
	"net"
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
					results = append(results, Device{
						IP:  net.IP(arp.SourceProtAddress).String(),
						MAC: net.HardwareAddr(arp.SourceHwAddress).String(),
					})
				}
			}
		case <-timeoutChan:
			return results, nil
		} // select
	} // for
} // listenForARPReplies
