package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"nhooyr.io/websocket"
)

type ProcessData struct {
	Pid         int32        `json:"pid"`
	Name        string       `json:"name"`
	Create_Time int64        `json:"create_time"`
	Update_Time int64        `json:"update_time"`
	Upload      int          `json:"upload"`
	Download    int          `json:"download"`
	Protocol    ProtocolData `json:"protocol"`
	Host        HostData     `json:"host"`
}

type ProtocolData struct {
	Protocol string
	Upload   int
	Download int
}

type HostData struct {
	Host     string
	Upload   int
	Download int
}

type ConnectionPorts struct {
	localAddressPort  uint32
	remoteAddressPort uint32
}

var (
	connections2pid map[ConnectionPorts]int32 = make(map[ConnectionPorts]int32) // Maps any connection (port to another port) to its respective PID
	all_macs        map[string]bool                                             // A makeshift set for storing the MAC address of all NICs
	proc_to_json    chan []byte               = make(chan []byte)               // Channel used to send the JSON data to the websocket server

	dataMutex = sync.RWMutex{}
)

// FIXME: Performance peaks at 40% CPU usage when downloading, optimize goroutines
func getConnections(interval int16) {
	for {
		// Get system-wide socket connections
		connections, err := net.Connections("all")

		// Log any errors
		if err != nil {
			log.Fatal(err)
		}

		// Map valid connections as {ConnectionPorts : PID}
		for _, conn := range connections {

			// Get this connection's PID
			pid := conn.Pid

			// Skip this iteration if either local or remote IPs don't exist
			if localAddr := conn.Laddr.IP; localAddr == "" {
				// log.Print("Local Address doesn't exist")
				continue
			}

			if remoteAddr := conn.Raddr.IP; remoteAddr == "" {
				// log.Print("Remote Address doesn't exist")
				continue
			}

			// Add the PID as entry in our map, using both ports as the key
			conn_ports := ConnectionPorts{localAddressPort: conn.Laddr.Port, remoteAddressPort: conn.Raddr.Port}

			dataMutex.Lock()
			connections2pid[conn_ports] = pid
			dataMutex.Unlock()
		}
		log.Println("Connections refreshed")
		time.Sleep(time.Second * time.Duration(interval))
	}
}

func getNetworkData(packet gopacket.Packet) (err error) {
	var (
		process_name               string
		total_payload              int
		process_data               ProcessData
		protocol_data              ProtocolData
		host_data                  HostData
		src_host, dst_host         string
		src_port, dst_port         uint32
		src_protocol, dst_protocol string
	)

	// Get port information
	if src_port, dst_port, err = getPortInfo(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get protocol information
	if src_protocol, dst_protocol, err = getProtocolName(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get PID from 'connection2pid' map
	if process_data.Pid, err = getPidFromConnection(src_port, dst_port); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get process name and creation time based on PID
	if process_data.Create_Time, process_name, err = getProcessInfo(process_data.Pid); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get packet payload
	if total_payload, err = getPayload(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get host address
	if src_host, dst_host, err = getNetworkAddresses(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Compare the packet's MAC address to the MAC addresses of this machine
	ethernet_layer := packet.Layer(layers.LayerTypeEthernet)
	src_mac := strings.ToLower(ethernet_layer.(*layers.Ethernet).SrcMAC.String())

	if _, ok := all_macs[src_mac]; ok { // Upload traffic
		host_data.Host = dst_host
		protocol_data.Protocol = dst_protocol

		process_data.Upload = total_payload
		host_data.Upload = total_payload
		protocol_data.Upload = total_payload
	} else { // Download traffic
		host_data.Host = src_host
		protocol_data.Protocol = src_protocol

		process_data.Download = total_payload
		host_data.Download = total_payload
		protocol_data.Download = total_payload
	}

	process_data.Name = process_name
	process_data.Update_Time = time.Now().UnixMilli()
	process_data.Host = host_data
	process_data.Protocol = protocol_data

	go jsonEncodeProcessData(process_data)

	return nil
}

// Returns source and destination addresses from a packet containing either an IPv4 or IPv6 layer
func getNetworkAddresses(packet gopacket.Packet) (src_ip string, dst_ip string, err error) {
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		switch netLayer.LayerType() {
		case layers.LayerTypeIPv4:
			return netLayer.(*layers.IPv4).SrcIP.String(), netLayer.(*layers.IPv4).DstIP.String(), nil
		case layers.LayerTypeIPv6:
			return netLayer.(*layers.IPv6).SrcIP.String(), netLayer.(*layers.IPv6).DstIP.String(), nil
		default:
			return "", "", errors.New("Packet contains neither IPv4 or IPv6 information")
		}
	}

	return "0", "0", errors.New("Packet doesn't contain a Network Layer")
}

// Returns the port number from the transport layer of a packet
// TODO: Some UDP Packets are being dropped; review those
func getPortInfo(packet gopacket.Packet) (src_port uint32, dst_port uint32, err error) {
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			return uint32(transportLayer.(*layers.TCP).SrcPort), uint32(transportLayer.(*layers.TCP).DstPort), nil
		case layers.LayerTypeUDP:
			return uint32(transportLayer.(*layers.UDP).SrcPort), uint32(transportLayer.(*layers.UDP).DstPort), nil
		default:
			return 0, 0, errors.New("Packet contains neither TCP or UDP information")
		}
	}

	return 0, 0, fmt.Errorf("Packet doesn't contain a Transport Layer")
}

// Returns protocol name if a port has a well-known port; otherwise, returns only the port number
func getProtocolName(packet gopacket.Packet) (src_protocol string, dst_protocol string, err error) {
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			return transportLayer.(*layers.TCP).SrcPort.String(), transportLayer.(*layers.TCP).DstPort.String(), nil
		case layers.LayerTypeUDP:
			return transportLayer.(*layers.UDP).SrcPort.String(), transportLayer.(*layers.UDP).DstPort.String(), nil
		default:
			return "0", "0", errors.New("Packet contains neither TCP or UDP information")
		}
	}

	return "", "", errors.New("Packet doesn't contain a Transport Layer")
}

// Get the PID from connections2pid, given source and destination ports
func getPidFromConnection(src_port, dst_port uint32) (pid int32, err error) {
	var conn_port = ConnectionPorts{localAddressPort: src_port, remoteAddressPort: dst_port}
	var conn_port_inv = ConnectionPorts{localAddressPort: dst_port, remoteAddressPort: src_port}

	dataMutex.Lock()
	if pid, ok := connections2pid[conn_port]; ok {
		dataMutex.Unlock()
		return pid, nil
	} else if pid, ok := connections2pid[conn_port_inv]; ok {
		dataMutex.Unlock()
		return pid, nil
	}

	dataMutex.Unlock()

	return 0, errors.New("PID not found for given ports")
}

// Get process creation time and name based on its PID
func getProcessInfo(pid int32) (create_time int64, proc_name string, err error) {
	if process, err := process.NewProcess(pid); err != nil {
		return 0, "", err
	} else {
		var time int64
		var name string

		// Get process creation time; otherwise, treat it as a system process and use boot time instead.
		if time, err = process.CreateTime(); err != nil {
			boot_time, err := host.BootTime()

			if err != nil {
				return 0, "", err
			}

			time = int64(boot_time)
		}

		if name, err = process.Name(); err != nil {
			return 0, "", err
		} else {
			return time, name, nil
		}
	}
}

// Get payload size from packet
// TODO: Review how the payload is collected. Some packets don't have payload, but the headers are still present in the network flow
func getPayload(packet gopacket.Packet) (payload int, err error) {
	if app_layer := packet.ApplicationLayer(); app_layer != nil {
		return len(app_layer.Payload()), nil // Add total payload bytes if ApplicationLayer exists
	} else if trans_layer := packet.TransportLayer(); trans_layer != nil {
		return len(trans_layer.LayerPayload()), nil // Otherwise, add total payload bytes if TransportLayer exists
	}

	return 0, errors.New("Unable to extract payload size from both Application and Transport layers")
}

// jsonEncodeProcessData takes a ProcessData object, encodes it into JSON and sends it to the proc_to_json channel, where it will be sent to the Websocket client.
func jsonEncodeProcessData(process_data ProcessData) {
	if json_str, err := json.Marshal(process_data); err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(string(json_str))
		proc_to_json <- json_str
	}
}

// websocketHandler opens the Websocket Server, waits for a connection and sends the 'proc_to_json' data
func websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		log.Printf("Failed to accept WebSocket connection: %v", err)
		return
	}

	log.Printf("Connected to Websocket client ")

	defer conn.Close(websocket.StatusInternalError, "Internal Server Error")

	for {

		data := <-proc_to_json

		if err := conn.Write(r.Context(), websocket.MessageText, data); err != nil {
			log.Printf("Failed to send message: %v", err)
			return
		}
	}
}

// startServer initializes the Websocket handle and assigns it to port 50000
func startServer() {
	http.HandleFunc("/websocket", websocketHandler)
	http.ListenAndServe(":50000", nil)
}

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

	// Set MAC addresses
	if macs, err := getMacAddresses(); err != nil {
		log.Fatal("Unable to retrieve MAC addresses")
	} else {
		all_macs = macs
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

	// Starts the Websocket server
	go startServer()

	// Create new goroutine for mapping connections to their respective PID
	go getConnections(5)

	// Create a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets from the packet source
	for packet := range packetSource.Packets() {
		// Print process data
		go getNetworkData(packet)
	}
	fmt.Println() // Print a newline at the end for cleaner termination
}
