package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// printUsage prints the usage instructions for the program

func printUsage() {
	fmt.Println("Usage: gocap -i <interface> [-f <filter>]")
	fmt.Println("Please specify the network interface to capture packets on.")
	fmt.Println("Optionally, you can specify a BPF filter with the -f flag.")
}

func main() {
	// Define command-line flags for the network interface and filter
	interfaceName := flag.String("i", "", "Network interface to capture packets on")
	filter := flag.String("f", "", "BPF filter for capturing specific packets")
	flag.Parse() // Parse command-line arguments

	// Check if the interface name was provided; if not, print usage instructions and exit
	if *interfaceName == "" {
		printUsage()
		return
	}

	// Open the specified network interface for packet capture
	handle, err := pcap.OpenLive(*interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err) // Log any error
	}

	defer handle.Close() // Ensure the handle is closed when finished

	// Apply the BPF filter if provided
	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatal(err) // Log any error setting the filter
		}
	}

	// Print the titles for the statistics
	fmt.Println("Packet Count | Total Bytes | Total Payload (Bytes) ")

	// Create a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Declare variables to keep track of packet statistics
	var packetCount, totalBytes, totalPayload int

	// Loop through packets from the packet source
	for packet := range packetSource.Packets() {
		packetCount++                    // Increment packet count
		totalBytes += len(packet.Data()) // Add total bytes

		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			totalPayload += len(appLayer.Payload()) // Add total payload bytes if ApplicationLayer exists
		} else if transLayer := packet.TransportLayer(); transLayer != nil {
			totalPayload += len(transLayer.LayerPayload()) // Otherwise, add total payload bytes if TransportLayer exists
		}

		// Print the statistics, updating the counters without printing new lines
		fmt.Printf("\r%13d | %12d | %18d", packetCount, totalBytes, totalPayload)
	}

	fmt.Println() // Print a newline at the end for cleaner termination

}
