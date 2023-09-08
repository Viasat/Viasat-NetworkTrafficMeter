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
		allMacs               map[string]bool                                               // A set for storing the MAC address of all network interfaces.
		activeConnections     map[string]*ConnectionData = make(map[string]*ConnectionData) // Maps all interactions between processes and the network.
		areConnectionsEncoded chan bool                  = make(chan bool, 1)               // Channel used to signal if the activeConnections maps were encoded, so that they can be reset for new connections.
	)

	// Define command-line flags for the network interface and filter
	interfaceName := flag.String("i", "", "Network interface to capture packets on")
	filter := flag.String("f", "", "BPF filter for capturing specific packets")
	verbose := flag.Bool("v", false, "Flag for displaying processing information")

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
	handle, err := pcap.OpenLive(*interfaceName, 1600, true, pcap.BlockForever)
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
	go StartServer()

	// Create a goroutine for mapping connections to their respective PID
	go GetSocketConnections(5, verbose)

	// Create a goroutine for encoding the activeConnections map into JSON
	go EncodeActiveConnections(&activeConnections, areConnectionsEncoded, verbose)

	// Create a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets from the packet source
	for packet := range packetSource.Packets() {
		/* If EncodeActiveConnections has finished encoding the data contained on the map, reset the map,
		so that the client receives the accumulated network traffic of the previous second
		*/
		select {
		case encoded := <-areConnectionsEncoded:
			if encoded {
				activeConnections = make(map[string]*ConnectionData)
			}
		default:
		}

		// Process the packet, and log error if the 'verbose' flag is set
		if err := GetNetworkData(packet, allMacs, activeConnections); err != nil && *verbose {
			log.Println(err.Error())
		}
	}

	// Print a newline at the end for cleaner termination
	fmt.Println()
}
