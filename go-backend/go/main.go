package main

import (
	"database/sql"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	connections2pid map[SocketConnectionPorts]SocketConnectionProcess = make(map[SocketConnectionPorts]SocketConnectionProcess)
	bufferParser    map[string]*ActiveProcess                         = make(map[string]*ActiveProcess)
	bufferDatabase  map[string]*ActiveProcess                         = make(map[string]*ActiveProcess)

	eth  layers.Ethernet
	ipv4 layers.IPv4
	ipv6 layers.IPv6
	tcp  layers.TCP
	udp  layers.UDP
)

// ManageParserBuffer sends the current activeProcesses map to ParseActiveProcesses every one second, and then resets the map.
func ManageParserBuffer(bufferParserChan chan map[string]*ActiveProcess, bufferParserMutex *sync.RWMutex) {
	var ticker = time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			bufferParserChan <- bufferParser
			bufferParserMutex.Lock()
			bufferParser = make(map[string]*ActiveProcess)
			bufferParserMutex.Unlock()
		}
	}
}

func ManageDatabaseBuffer(db *sql.DB, bufferDatabaseMutex *sync.RWMutex) {
	var ticker = time.NewTicker(5 * time.Minute)
	defer InsertActiveProcessWithRelatedData(db, bufferDatabase)
	for {
		select {
		case <-ticker.C:
			log.Println("Saving to database...")
			bufferDatabaseMutex.Lock()
			if err := InsertActiveProcessWithRelatedData(db, bufferDatabase); err != nil {
				log.Println("Failed saving data to database: ", err)
			} else {
				log.Println("Saving complete")
			}
			bufferDatabase = make(map[string]*ActiveProcess)
			bufferDatabaseMutex.Unlock()
		}
	}
}

// ManageHandle receives a network interface's name from the 'networkInterface' channel and returns a handle on the 'updatedHandle' channel if no errors occur.
func ManageHandle(networkInterface chan string, updatedHandle chan *pcap.Handle) {
	for iface := range networkInterface {
		if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
			log.Println(err)
		} else {
			updatedHandle <- handle
		}
	}
}

func main() {
	var (
		packet     gopacket.Packet // packet stores the packet information to extract the payload.
		packetData []byte          // packetData Stores the packet data to use on the layer decoder.
		macs       []string        // macs stores an array of this machine's MAC addresses.
		payload    uint64          // payload stores the packet payload in bytes.
		db         *sql.DB         // db stores the database handle used in the webserver

		err error // err stores any errors from function returns.

		getConnectionsMutex = sync.RWMutex{} // getConnectionMutex is a mutex used to control read/write operations in the connections2pid map.
		bufferParserMutex   = sync.RWMutex{} // bufferMutex is a mutex used to control read/write operations in the activeProcesses map.
		bufferDatabaseMutex = sync.RWMutex{} // bufferMutex is a mutex used to control read/write operations in the activeProcesses map.

		bufferParserChan     chan map[string]*ActiveProcess = make(chan map[string]*ActiveProcess)
		networkInterfaceChan chan string                    = make(chan string, 1)
		updatedHandleChan    chan *pcap.Handle              = make(chan *pcap.Handle)
	)

	// Set MAC addresses
	if macs, err = GetMacAddresses(); err != nil {
		log.Fatal("Unable to retrieve MAC addresses: ", err)
	}

	// Start the database
	if db, err = OpenDatabase(); err != nil {
		log.Fatal("Unable to open database: ", err)
	}

	// Starts the web server
	go StartWebserver(networkInterfaceChan, db)

	// Waits for the client to inform a network interface, then open it for packet capture
	log.Println("Waiting for interface")
	handle, err := pcap.OpenLive(<-networkInterfaceChan, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err) // Log any error
	}

	// Ensure the handle is closed when finished
	defer handle.Close()

	// Manage handle switching by the client at runtime
	go ManageHandle(networkInterfaceChan, updatedHandleChan)

	// Creates a new decoding layer parser and a buffer to store the decoded layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	// Starts mapping processes in relation to their sockets.
	go GetSocketConnections(1, &getConnectionsMutex)

	// Sends the active processes within 1 second to the client
	go ManageParserBuffer(bufferParserChan, &bufferParserMutex)

	// Send the active processes within 5 minutes to the database
	go ManageDatabaseBuffer(db, &bufferDatabaseMutex)

	// Parse the active processes into JSON in intervals of 1 second.
	go ParseActiveProcesses(bufferParserChan)

	// Get packets and process them into useful data.
	for {
		// Check if a new handle is available
		select {
		case newHandle := <-updatedHandleChan:
			handle.Close()
			handle = newHandle
		default:
		}

		// Read packets from the handle.
		if data, _, err := handle.ReadPacketData(); err != nil {
			continue
		} else {
			// Store the data to use on the decoding layer parser.
			packetData = data

			// Use the data to create a new packet. This packet is used only to extract payload information.
			packet = gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)

			if payloadLayer := packet.Layer(gopacket.LayerTypePayload); payloadLayer != nil {
				payload = uint64(len(payloadLayer.LayerContents())) // Extract the payload information from the application layer
			}
		}

		// Decode the layers and store them in the 'decoded' buffer.
		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			continue
		}

		// Lock the activeProcesses map and process the packet.
		bufferParserMutex.Lock()
		bufferDatabaseMutex.Lock()
		ProcessPacket(decoded, macs, payload, &getConnectionsMutex, bufferParser, bufferDatabase)
		bufferParserMutex.Unlock()
		bufferDatabaseMutex.Unlock()
	}
}
