package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func handlePacket(packet gopacket.Packet) {
	fmt.Println(packet)
}

func capture(device string, bpfFilter string, snaplen int32, promiscuousMode bool) {
	if handle, err := pcap.OpenLive(device, snaplen, promiscuousMode, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpfFilter); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}

func main() {
	// Uncomment the line below to find which network interface you want to analyze
	// fmt.Print(pcap.FindAllDevs())
	device := "\\Device\\NPF_{4B8B39A3-C20B-4612-B6D5-438E2513AB15}"
	bpfFilter := "tcp and port 80"
	snaplen := 1600
	promiscuousMode := true

	capture(device, bpfFilter, int32(snaplen), promiscuousMode)

}
