package main

import (
	"flag"

	"fmt"

	"log"

	"strings"

	"github.com/AllenDang/giu"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

var packetHeaders []string

// printUsage prints the usage instructions for the program

func printUsage() {

	fmt.Println("Usage: gocap -i <interface> [-f <filter>]")

	fmt.Println("Please specify the network interface to capture packets on.")

	fmt.Println("Optionally, you can specify a BPF filter with the -f flag.")

}

// updatePacketHeaders adds a new packet header string to the list

func updatePacketHeaders(header string) {

	packetHeaders = append(packetHeaders, header)

	if len(packetHeaders) > 100 { // Keep the list manageable in size

		packetHeaders = packetHeaders[1:]

	}

}

// renderHeaders is a Giu widget that renders the packet headers

func renderHeaders() giu.Widget {

	return giu.Custom(func() {

		giu.Layout{

			giu.Label(strings.Join(packetHeaders, "\n")),
		}.Build()

	})

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

	fmt.Println("Packet Count | Total Bytes | Total Payload Bytes | Total Payload with Header Bytes")

	// Create a packet source to process packets

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Declare variables to keep track of packet statistics

	var packetCount, totalBytes, totalPayloadBytes, totalPayloadWithHeaderBytes int

	go func() {

		for packet := range packetSource.Packets() {

			packetCount++ // Increment packet count

			totalBytes += len(packet.Data()) // Add total bytes

			if appLayer := packet.ApplicationLayer(); appLayer != nil {

				totalPayloadBytes += len(appLayer.Payload()) // Add total payload bytes if ApplicationLayer exists

			}

			if transLayer := packet.TransportLayer(); transLayer != nil {

				totalPayloadWithHeaderBytes += len(transLayer.LayerPayload()) // Add total payload with header bytes if TransportLayer exists

			}

			// Print the statistics, updating the counters without printing new lines

			fmt.Printf("\r%13d | %12d | %18d | %29d", packetCount, totalBytes, totalPayloadBytes, totalPayloadWithHeaderBytes)

			// Update headers in the separate window

			headerDetails := fmt.Sprintf("Packet #%d:\n%s\n", packetCount, packet.String())

			updatePacketHeaders(headerDetails)

		}

		fmt.Println() // Print a newline at the end for cleaner termination

	}()

	// Set up Giu window to display detailed packet headers

	giu.NewMasterWindow("Packet Headers", 800, 600, 0).Run(func() {

		giu.SingleWindow().Layout(

			renderHeaders(),
		)

	})

}
