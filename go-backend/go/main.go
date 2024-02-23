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
	bufferDatabase  []map[string]*ActiveProcess                         = make([]map[string]*ActiveProcess, 0)

	eth  layers.Ethernet
	ipv4 layers.IPv4
	ipv6 layers.IPv6
	tcp  layers.TCP
	udp  layers.UDP
)

// ManageParserBuffer sends the current activeProcesses map to ParseActiveProcesses every one second, and then resets the map.
func ManageParserBuffer(bufferParserChan chan map[string]*ActiveProcess, bufferParserMutex, bufferDatabaseMutex *sync.RWMutex) {
	var ticker = time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			bufferParserChan <- bufferParser
			bufferParserMutex.Lock()
			bufferDatabaseMutex.Lock()
			bufferParser = make(map[string]*ActiveProcess)
			bufferDatabase = append(bufferDatabase, make(map[string]*ActiveProcess))
			bufferDatabaseMutex.Unlock()
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
			SaveBufferToDatabase(db, bufferDatabaseMutex)
		}
	}
}

func SaveBufferToDatabase(db *sql.DB, bufferDatabaseMutex *sync.RWMutex) {
	log.Println("Saving to database...")
	bufferDatabaseMutex.Lock()
	if err := InsertActiveProcessWithRelatedData(db, bufferDatabase); err != nil {
		log.Println("Failed saving data to database: ", err)
	} else {
		log.Println("Saving complete")
	}
	bufferDatabase = make([]map[string]*ActiveProcess, 0)
	bufferDatabase = append(bufferDatabase, make(map[string]*ActiveProcess))

	bufferDatabaseMutex.Unlock()
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

// CreateHandle receives a network interface's name and returns a handle if no errors occur.
func CreateHandle(networkInterface string) (*pcap.Handle, error) {
	if handle, err := pcap.OpenLive(networkInterface, 1600, true, pcap.BlockForever); err != nil {
		log.Println(err)
		return nil, err
	} else {
		return handle, nil
	}
}

// Compare current interfaces with new ones
func CheckInterfaces(oldInterfaces []NetworkInterface, newInterfaces []NetworkInterface) (addedInterfaces []NetworkInterface, removedInterfaces []NetworkInterface) {
	addedInterfaces = make([]NetworkInterface, 0)
	removedInterfaces = make([]NetworkInterface, 0)

	for _, oldInterface := range oldInterfaces {
		found := false
		for _, newInterface := range newInterfaces {
			if oldInterface.Name == newInterface.Name {
				found = true
				break
			}
		}
		if !found {
			removedInterfaces = append(removedInterfaces, oldInterface)
		}
	}

	for _, newInterface := range newInterfaces {
		found := false
		for _, oldInterface := range oldInterfaces {
			if oldInterface.Name == newInterface.Name {
				found = true
				break
			}
		}
		if !found {
			addedInterfaces = append(addedInterfaces, newInterface)
		}
	}

	return addedInterfaces, removedInterfaces
}

func main() {
	var (
		packet     gopacket.Packet // packet stores the packet information to extract the payload.
		packetData []byte          // packetData Stores the packet data to use on the layer decoder.
		macs       []string        // macs stores an array of this machine's MAC addresses.
		payload    uint64          // payload stores the packet payload in bytes.
		db         *sql.DB         // db stores the database handle used in the webserver

		stopSignal                           = make(map[string]chan bool)  // Channel to signal goroutines to stop
		currentInterfaces []NetworkInterface = make([]NetworkInterface, 0) // list of available interfaces

		err error // err stores any errors from function returns.

		getConnectionsMutex = sync.RWMutex{} // getConnectionMutex is a mutex used to control read/write operations in the connections2pid map.
		bufferParserMutex   = sync.RWMutex{} // bufferMutex is a mutex used to control read/write operations in the activeProcesses map.
		bufferDatabaseMutex = sync.RWMutex{} // bufferMutex is a mutex used to control read/write operations in the activeProcesses map.

		bufferParserChan chan map[string]*ActiveProcess = make(chan map[string]*ActiveProcess)
		
		shutdownChan chan bool = make(chan bool) // channel used for shuting down the application
	)

	bufferDatabase = append(bufferDatabase, make(map[string]*ActiveProcess))

	// Set MAC addresses
	if macs, err = GetMacAddresses(); err != nil {
		log.Fatal("Unable to retrieve MAC addresses: ", err)
	}

	// Start the database
	if db, err = OpenDatabase(); err != nil {
		log.Fatal("Unable to open database: ", err)
	}

	// Starts the web server
	go StartWebserver(db, &bufferDatabaseMutex, shutdownChan)

	// Creates a new decoding layer parser and a buffer to store the decoded layers.
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	// Starts mapping processes in relation to their sockets.
	go GetSocketConnections(1, &getConnectionsMutex)

	// Sends the active processes within 1 second to the client
	go ManageParserBuffer(bufferParserChan, &bufferParserMutex, &bufferDatabaseMutex)

	// Send the active processes within 5 minutes to the database
	go ManageDatabaseBuffer(db, &bufferDatabaseMutex)

	// Parse the active processes into JSON in intervals of 1 second.
	go ParseActiveProcesses(bufferParserChan)

	for {
		select {
		case <-shutdownChan:
			SaveBufferToDatabase(db, &bufferDatabaseMutex)
			for _, iface := range currentInterfaces {
				log.Println("Closing interface: ", iface.Description)
				close(stopSignal[iface.Name])
			}
			return
		default:
			// Gets interfaces
			if ifaces, err := GetInterfaceList(); err != nil {
				log.Fatal("Unable to retrieve interfaces")
			} else {
				addedInterfaces, removedInterfaces := CheckInterfaces(currentInterfaces, ifaces)
				currentInterfaces = ifaces
				if len(removedInterfaces) > 0 {
					//Removes interfaces not found
					for _, iface := range removedInterfaces {
						log.Println("Removed interface: ", iface.Description)
						close(stopSignal[iface.Name])
					}
				}
				if len(addedInterfaces) > 0 {
					// Loop through the new interfaces
					for _, iface := range addedInterfaces {

						// Create a handle for the interface.
						if handle, err := CreateHandle(iface.Name); err != nil {
							log.Println("Unable do handle interface: ", iface.Description)
							continue
						} else {
							log.Println("Added interface: ", iface.Description)

							// Create the stop signal channel for this interface
							stopSignal[iface.Name] = make(chan bool)

							// Create the go routine for this interface
							go func(handle *pcap.Handle, iface NetworkInterface, stopSignal chan bool) {
								for {
									select {
									case <-stopSignal:
										handle.Close()
										return
									default:
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
										lastBufferDatabase := bufferDatabase[len(bufferDatabase)-1]
										ProcessPacket(decoded, macs, payload, &getConnectionsMutex, bufferParser, lastBufferDatabase)
										bufferParserMutex.Unlock()
										bufferDatabaseMutex.Unlock()
									}
								}
							}(handle, iface, stopSignal[iface.Name])
						}
					}
				}
			}
		}

		time.Sleep(time.Second)
	}
}
