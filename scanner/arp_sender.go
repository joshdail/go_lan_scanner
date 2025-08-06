package scanner

import (
	"log"

	"github.com/google/gopacket/pcap"
)

func sendARPRequests(handle *pcap.Handle, packets [][]byte) error {
	for _, pkt := range packets {
		if err := handle.WritePacketData(pkt); err != nil {
			log.Println("send error:", err)
		}
	}
	return nil
} // sendARPRequests
