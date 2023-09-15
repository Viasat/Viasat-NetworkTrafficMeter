package main

import (
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	connections2pid     map[ConnectionPorts]int32 = make(map[ConnectionPorts]int32) // Maps any connection (port to another port) to its respective PID.
	getConnectionsMutex                           = sync.RWMutex{}                  // A mutual exclusion lock to prevent simultaneous read/write access to the 'connections2pid' map
)

func main() {
	var (
		allMacs               map[string]bool                 // A set for storing the MAC address of all network interfaces.
		workChan              chan gopacket.Packet            = make(chan gopacket.Packet)
		processedPacketChan   chan ProcessedPacket            = make(chan ProcessedPacket)
		activeConnectionsChan chan map[string]*ConnectionData = make(chan map[string]*ConnectionData)
	)

	// Define command-line flags for the network interface and filter
	interfaceName := flag.String("i", "", "Network interface to capture packets on")
	filter := flag.String("f", "", "BPF filter for capturing specific packets")
	verbose := flag.Bool("v", false, "Flag for displaying processing information")
	noClient := flag.Bool("no-client", false, "Runs the backend without a websocket server. If true, the data is printed to the console.")

	// Parse command-line arguments
	flag.Parse()

	// Check if the interface name was provided; if not, show instructions and list of available interfaces
	if *interfaceName == "" {
		PrintUsage()
		if dev, err := GetInterfaceFromList(); err != nil {
			log.Fatal(err)
		} else {
			*interfaceName = dev // If the interface choice is valid, get its name for initializing the handle
		}
	}

	// Set MAC addresses
	if macs, err := GetMacAddresses(); err != nil {
		log.Fatal("Unable to retrieve MAC addresses")
	} else {
		allMacs = macs
	}

	// Open the specified network interface for packet capture
	handle, err := pcap.OpenLive(*interfaceName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err) // Log any error
	}

	// Ensure the handle is closed when finished
	defer handle.Close()

	// Apply the BPF filter if provided
	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Fatal(err) // Log any error setting the filter
		}
	}

	// Starts the Websocket server
	if !*noClient {
		go StartServer()
	}

	// Create a goroutine for mapping connections to their respective PID
	go GetSocketConnections(5, verbose)

	// Creates a worker pool to process packets
	for i := 0; i < 10; i++ {
		go PacketProcesser(workChan, allMacs, processedPacketChan)
	}

	// Create a goroutine to buffer ProcessedPackets
	go ConnectionsBufferer(processedPacketChan, activeConnectionsChan)

	// Create a goroutine for parsing the buffer into JSON
	go EncodeActiveConnections(activeConnectionsChan, noClient)

	// Create a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets from the packet source
	for packet := range packetSource.Packets() {
		workChan <- packet
	}

	// Print a newline at the end for cleaner termination
	fmt.Println()
}
