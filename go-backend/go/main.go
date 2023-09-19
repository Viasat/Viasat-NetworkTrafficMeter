package main

import (
	"flag"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	connections2pid map[SocketConnectionPorts]SocketConnectionProcess = make(map[SocketConnectionPorts]SocketConnectionProcess)
	activeProcesses map[string]*ActiveProcess                         = make(map[string]*ActiveProcess)

	eth  layers.Ethernet
	ipv4 layers.IPv4
	ipv6 layers.IPv6
	tcp  layers.TCP
	udp  layers.UDP
)

func main() {
	var (
		packet     gopacket.Packet // packet stores the packet information to extract the payload.
		packetData []byte          // packetData Stores the packet data to use on the layer decoder.
		payload    int             // payload stores the packet payload in bytes.
		macs       []string        // macs stores an array of this machine's MAC addresses.
		err        error           // err stores any errors from function returns.

		getConnectionsMutex  = sync.RWMutex{} // getConnectionMutex is a mutex used to control read/write operations in the connections2pid map.
		activeProcessesMutex = sync.RWMutex{} // bufferMutex is a mutex used to control read/write operations in the activeProcesses map.

		areProcessesEncoded chan bool = make(chan bool, 1)
	)

	// Define command-line flags for the network interface and filter
	interfaceName := flag.String("i", "", "Network interface to capture packets on")
	filter := flag.String("f", "", "BPF filter for capturing specific packets")

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
	if macs, err = GetMacAddresses(); err != nil {
		log.Fatal("Unable to retrieve MAC addresses")
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

	// Creates a new decoding layer parser and a buffer to store the decoded layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	// Starts the Websocket server
	go StartServer()

	// Starts mapping processes in relation to their sockets.
	go GetSocketConnections(1, &getConnectionsMutex)

	// Parse the active processes into JSON in intervals of 1 second.
	go ParseActiveProcesses(&activeProcesses, areProcessesEncoded, &activeProcessesMutex)

	// Get packets and process them into useful data.
	for {

		// If the active processes were encoded, reset the map.
		select {
		case encoded := <-areProcessesEncoded:
			if encoded {
				activeProcessesMutex.Lock()
				activeProcesses = make(map[string]*ActiveProcess)
				activeProcessesMutex.Unlock()
			}
		default:
		}

		// Read packets from the handle.
		if data, _, err := handle.ReadPacketData(); err != nil {
			continue
		} else {
			// Store the data to use on the decoding layer parser.
			packetData = data

			// Use the data to create a new packet. This packet is used only to extract payload information.
			packet = gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload = len(appLayer.Payload()) // Extract the payload information from the application layer
			}
		}

		// Decode the layers and store them in the 'decoded' buffer.
		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			continue
		}

		// Process the packet.
		ProcessPacket(decoded, macs, payload, &getConnectionsMutex)
	}
}
