package main

import (
	"flag"
	"log"
	"sync"
	"time"

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

// ManageActiveProcessesBuffer sends the current activeProcesses map to ParseActiveProcesses every one second, and then resets the map.
func ManageActiveProcessesBuffer(activeProcessesChan chan map[string]*ActiveProcess, activeProcessesMutex *sync.RWMutex) {
	var ticker = time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			activeProcessesChan <- activeProcesses
			activeProcessesMutex.Lock()
			activeProcesses = make(map[string]*ActiveProcess)
			activeProcessesMutex.Unlock()
		}
	}
}

func main() {
	var (
		packet     gopacket.Packet // packet stores the packet information to extract the payload.
		packetData []byte          // packetData Stores the packet data to use on the layer decoder.
		macs       []string        // macs stores an array of this machine's MAC addresses.
		payload    int             // payload stores the packet payload in bytes.

		err error // err stores any errors from function returns.

		getConnectionsMutex  = sync.RWMutex{} // getConnectionMutex is a mutex used to control read/write operations in the connections2pid map.
		activeProcessesMutex = sync.RWMutex{} // bufferMutex is a mutex used to control read/write operations in the activeProcesses map.

		activeProcessesChan chan map[string]*ActiveProcess = make(chan map[string]*ActiveProcess)
		selectedIfaceChan   chan string                    = make(chan string, 1)
	)

	// Define command-line flags for the network interface and filter
	interfaceName := flag.String("i", "", "Network interface to capture packets on")
	legacyMode := flag.Bool("legacy", false, "Legacy mode, where the interface must be chosen from the backend.")

	// Parse command-line arguments
	flag.Parse()

	// Set MAC addresses
	if macs, err = GetMacAddresses(); err != nil {
		log.Fatal("Unable to retrieve MAC addresses")
	}

	// Starts the Websocket server
	go StartServer(selectedIfaceChan, legacyMode)

	log.Println("Waiting for interface")
	if *legacyMode {
		if *interfaceName == "" {
			PrintUsage()
			if dev, err := GetInterfaceFromList(); err != nil {
				log.Fatal(err)
			} else {
				*interfaceName = dev // If the interface choice is valid, get its name for initializing the handle
			}
		}
		selectedIfaceChan <- *interfaceName
	}

	// Open the specified network interface for packet capture
	handle, err := pcap.OpenLive(<-selectedIfaceChan, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err) // Log any error
	}
	log.Println("Interface received")

	// Ensure the handle is closed when finished
	defer handle.Close()

	// Creates a new decoding layer parser and a buffer to store the decoded layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	// Starts mapping processes in relation to their sockets.
	go GetSocketConnections(1, &getConnectionsMutex)

	go ManageActiveProcessesBuffer(activeProcessesChan, &activeProcessesMutex)

	// Parse the active processes into JSON in intervals of 1 second.
	go ParseActiveProcesses(activeProcessesChan)

	// Get packets and process them into useful data.
	for {
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

		// Lock the activeProcesses map and process the packet.
		activeProcessesMutex.Lock()
		ProcessPacket(decoded, macs, payload, &getConnectionsMutex)
		activeProcessesMutex.Unlock()
	}
}
