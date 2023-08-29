package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type ProcessData struct {
	pid              int32
	name             string
	created_time     int64
	last_update_time int64
	upload           int
	download         int
	protocols        []ProtocolData
	hosts            []HostData
}

type ProtocolData struct {
	protocol string
	upload   int
	download int
}

type HostData struct {
	host     string
	upload   int
	download int
}

type ConnectionPorts struct {
	localAddressPort  uint32
	remoteAddressPort uint32
}

var (
	// connections2pid map[ConnectionPorts]int32 = make(map[ConnectionPorts]int32) // Maps any connection (port to another port) to its respective PID
	pid2proc_data map[string]ProcessData = make(map[string]ProcessData) // Map to relate a process name to its application
	all_macs      map[string]bool                                       // A makeshift set for storing the MAC address of all NICs
)

// FIXME: Performance peaks at 40% CPU usage when downloading, optimize goroutines
func getConnections(connections2pid chan<- map[ConnectionPorts]int32) {
	for {
		// Create a new connection map
		var conn2pid map[ConnectionPorts]int32 = make(map[ConnectionPorts]int32)

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

			conn2pid[conn_ports] = pid
		}

		connections2pid <- conn2pid
	}
}

func getNetworkData(packet gopacket.Packet, connections2pid <-chan map[ConnectionPorts]int32) (proc ProcessData, err error) {
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
		return ProcessData{}, err
	}

	// Get protocol information
	if src_protocol, dst_protocol, err = getProtocolName(packet); err != nil {
		//log.Fatal(err)
		return ProcessData{}, err
	}

	conn2pid := <-connections2pid

	// Get PID from 'connection2pid' map
	if process_data.pid, err = getPidFromConnection(src_port, dst_port, conn2pid); err != nil {
		//log.Fatal(err)
		return ProcessData{}, err
	}

	// Get process name and creation time based on PID
	if process_data.created_time, process_name, err = getProcessInfo(process_data.pid); err != nil {
		//log.Fatal(err)
		return ProcessData{}, err
	}

	// Get packet payload
	if total_payload, err = getPayload(packet); err != nil {
		//log.Fatal(err)
		return ProcessData{}, err
	}

	// Get host address
	if src_host, dst_host, err = getNetworkAddresses(packet); err != nil {
		//log.Fatal(err)
		return ProcessData{}, err
	}

	// Compare the packet's MAC address to the MAC addresses of this machine
	ethernet_layer := packet.Layer(layers.LayerTypeEthernet)
	src_mac := strings.ToLower(ethernet_layer.(*layers.Ethernet).SrcMAC.String())

	if _, ok := all_macs[src_mac]; ok { // Upload traffic
		host_data.host = dst_host
		protocol_data.protocol = dst_protocol

		process_data.upload = total_payload
		host_data.upload = total_payload
		protocol_data.upload = total_payload
	} else { // Download traffic
		host_data.host = src_host
		protocol_data.protocol = src_protocol

		process_data.download = total_payload
		host_data.download = total_payload
		protocol_data.download = total_payload
	}

	process_data.name = process_name
	process_data.last_update_time = time.Now().UnixMilli()

	// pid2proc_data[process_name] = process_data

	return process_data, nil
}

// Returns source and destination addresses from a packet containing either an IPv4 or IPv6 layer
func getNetworkAddresses(packet gopacket.Packet) (src_ip string, dst_ip string, err error) {
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		switch netLayer.LayerType() {
		case layers.LayerTypeIPv4:
			return string(netLayer.(*layers.IPv4).SrcIP), string(netLayer.(*layers.IPv4).DstIP), nil
		case layers.LayerTypeIPv6:
			return string(netLayer.(*layers.IPv6).SrcIP), string(netLayer.(*layers.IPv6).DstIP), nil
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
func getPidFromConnection(src_port, dst_port uint32, conn2pid map[ConnectionPorts]int32) (pid int32, err error) {
	var conn_port = ConnectionPorts{localAddressPort: src_port, remoteAddressPort: dst_port}
	var conn_port_inv = ConnectionPorts{localAddressPort: dst_port, remoteAddressPort: src_port}

	if pid, ok := conn2pid[conn_port]; ok {
		return pid, nil
	} else if pid, ok := conn2pid[conn_port_inv]; ok {
		return pid, nil
	}

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

	// Creates a map relating connections and their PIDs.
	// Used as a channel variable between 'getConnections' (writer) and getNetworkData
	var connections2pid chan map[ConnectionPorts]int32 = make(chan map[ConnectionPorts]int32)

	// Create new thread for mapping connections to their respective PID
	go getConnections(connections2pid)

	// Create a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop through packets from the packet source
	for packet := range packetSource.Packets() {
		// Print process data
		if _, err := getNetworkData(packet, connections2pid); err != nil {
			fmt.Println(err.Error())
		}
	}

	fmt.Println() // Print a newline at the end for cleaner termination

}
