package main

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	ps_host "github.com/shirou/gopsutil/v3/host"
	ps_net "github.com/shirou/gopsutil/v3/net"
	ps_process "github.com/shirou/gopsutil/v3/process"
)

// ConnectionData stores the name of a process, its total download and upload and specific information about its subprocesses, protocols and hosts.
type ConnectionData struct {
	Name      string
	Upload    int
	Download  int
	Processes map[int32]*ProcessData
	Protocols map[string]*ProtocolData
	Hosts     map[string]*HostData
}

// ProcessData stores a Process' ID, its individual network consumption as well as time of creation and last update.
type ProcessData struct {
	Pid         int32
	Create_Time int64
	Update_Time int64
	Upload      int
	Download    int
}

// ProtocolData stores the port number along with its well-known protocol name (if it has one) and its individual network consumption.
type ProtocolData struct {
	Protocol_Name string
	Upload        int
	Download      int
}

// HostData stores the IP address of an external host communicating with the associated process, as well as its individual network consumption.
type HostData struct {
	Host_Name string
	Upload    int
	Download  int
}

// ConnectionPorts serves as a tuple for storing the local address port and remote address port.
// This is used as a key for mapping PIDs to the port used by the process
type ConnectionPorts struct {
	localAddressPort  uint32
	remoteAddressPort uint32
}

var (
	pid                      int32
	createTime               int64
	processName              string
	payload                  int
	srcHost, dstHost         string
	srcPort, dstPort         uint32
	srcProtocol, dstProtocol string
	connectionData           *ConnectionData
)

// GetConnections maps any socket connection to its PID. The interval parameter is the refresh rate (in seconds) of this function.
func GetSocketConnections(interval int16, verbose *bool) {
	var (
		connections []ps_net.ConnectionStat
		err         error
	)

	for {
		// Get system-wide socket connections
		connections, err = ps_net.Connections("all")

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
			connectionPorts := ConnectionPorts{localAddressPort: conn.Laddr.Port, remoteAddressPort: conn.Raddr.Port}

			getConnectionsMutex.Lock()
			connections2pid[connectionPorts] = pid
			getConnectionsMutex.Unlock()
		}

		if *verbose {
			log.Println("Connections refreshed")
		}

		time.Sleep(time.Second * time.Duration(interval))
	}
}

// FIXME: CPU usage increases the more packets are being processed per second. Review possible bottlenecks using 'pprof'
// GetNetworkData processes a packet into a ConnectionData object and stores it into the activeConnections map
func GetNetworkData(packet gopacket.Packet, allMacs map[string]bool, activeConnections map[string]*ConnectionData) (err error) {

	// Get port information
	if srcPort, dstPort, srcProtocol, dstProtocol, err = GetPortAndProtocol(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get PID from 'connection2pid' map
	if pid, err = GetPidFromConnection(srcPort, dstPort); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get process name and creation time based on PID
	if createTime, processName, err = GetProcessData(pid); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get packet payload
	if payload, err = GetPayload(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Get host address
	if srcHost, dstHost, err = GetNetworkAddresses(packet); err != nil {
		//log.Fatal(err)
		return err
	}

	// Create a new connection in the active connections map if one doesn't exist
	if _, ok := activeConnections[processName]; !ok {
		connection := CreateConnection(processName)
		activeConnections[processName] = connection
	}

	// Get connection data from active connections
	connectionData = activeConnections[processName]

	// Compare the packet's MAC address to the MAC addresses of this machine
	ethernet_layer := packet.Layer(layers.LayerTypeEthernet)
	srcMac := strings.ToLower(ethernet_layer.(*layers.Ethernet).SrcMAC.String())

	// Update connection data
	if _, ok := allMacs[srcMac]; ok { // Upload traffic
		UpdateConnection(connectionData, pid, createTime, dstProtocol, dstHost, 0, payload)
	} else { // Download traffic
		UpdateConnection(connectionData, pid, createTime, srcProtocol, srcHost, payload, 0)
	}

	return nil
}

// GetNworkaddreses Returns source and destination IP addresses from a packet containing either an IPv4 or IPv6 layer
func GetNetworkAddresses(packet gopacket.Packet) (srcIp string, dstIp string, err error) {
	// Check if network layer exists and is of type IPv4 and IPv6
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

// GetPortAndPortocolReturns the port number and well-known protocol name associated to the port from the transport layer of a packet
// TODO: Some UDP Packets are being dropped; review those
func GetPortAndProtocol(packet gopacket.Packet) (srcPort uint32, dstPort uint32, srcProtocol string, dstProtocol string, err error) {
	// Check if transport layer exists and is of type TCP/UDP
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			return uint32(transportLayer.(*layers.TCP).SrcPort), uint32(transportLayer.(*layers.TCP).DstPort),
				transportLayer.(*layers.TCP).SrcPort.String(), transportLayer.(*layers.TCP).DstPort.String(), nil
		case layers.LayerTypeUDP:
			return uint32(transportLayer.(*layers.UDP).SrcPort), uint32(transportLayer.(*layers.UDP).DstPort),
				transportLayer.(*layers.UDP).SrcPort.String(), transportLayer.(*layers.UDP).DstPort.String(), nil
		default:
			return 0, 0, "", "", errors.New("Packet contains neither TCP or UDP information")
		}
	}

	return 0, 0, "", "", errors.New("Packet doesn't contain a Transport Layer")
}

// Get the PID from connections2pid, given source and destination ports
func GetPidFromConnection(srcPort, dstPort uint32) (pid int32, err error) {
	// Createa tuple for the ports in both directions, depending if its download or upload
	var conn_port = ConnectionPorts{localAddressPort: srcPort, remoteAddressPort: dstPort}
	var conn_port_inv = ConnectionPorts{localAddressPort: dstPort, remoteAddressPort: srcPort}

	// Lock the connections2pid map
	getConnectionsMutex.Lock()

	// Ensure its unlocked after this functions returns
	defer getConnectionsMutex.Unlock()

	// Check if these ports are linked to a PID
	if pid, ok := connections2pid[conn_port]; ok {
		return pid, nil
	} else if pid, ok := connections2pid[conn_port_inv]; ok {
		return pid, nil
	}

	return 0, errors.New("PID not found for given ports")
}

// Get process creation time and name based on its PID
func GetProcessData(pid int32) (createTime int64, procName string, err error) {
	// Check if process exists for the given pid
	if process, err := ps_process.NewProcess(pid); err != nil {
		return 0, "", err
	} else {
		// Get process creation time; otherwise, treat it as a system process and use boot time instead.
		if createTime, err = process.CreateTime(); err != nil {
			if bootTime, err := ps_host.BootTime(); err != nil {
				return 0, "", err
			} else {
				createTime = int64(bootTime)
			}
		}

		// Check if process name can be retrieved
		if procName, err = process.Name(); err != nil {
			return 0, "", err
		} else {
			return createTime, procName, nil
		}
	}
}

// Get payload size from packet
// TODO: Review how the payload is collected. Some packets don't have payload, but the headers are still present in the network flow
func GetPayload(packet gopacket.Packet) (payload int, err error) {
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		return len(appLayer.Payload()), nil // Add total payload bytes if ApplicationLayer exists
	} else if transLayer := packet.TransportLayer(); transLayer != nil {
		return len(transLayer.LayerPayload()), nil // Otherwise, add total payload bytes if TransportLayer exists
	}

	return 0, errors.New("Unable to extract payload size from both Application and Transport layers")
}

// CreateConnection creates a new ConnectionData object to be used in the activeConnections map
func CreateConnection(process_name string) (connection *ConnectionData) {
	connection = &ConnectionData{Name: process_name}
	connection.Processes = make(map[int32]*ProcessData)
	connection.Protocols = make(map[string]*ProtocolData)
	connection.Hosts = make(map[string]*HostData)

	return connection
}

// UpdateConnection updates a ConnectionData object according to the packet data
func UpdateConnection(connection *ConnectionData, pid int32, create_time int64, protocol string, host string, download int, upload int) {
	// Create a new entry in the Processes map if the PID is not found
	if _, ok := connection.Processes[pid]; !ok {
		connection.Processes[pid] = &ProcessData{Pid: pid, Create_Time: create_time}
	}

	// Create a new entry in the Protocols map if the protocol is not found
	if _, ok := connection.Protocols[protocol]; !ok {
		connection.Protocols[protocol] = &ProtocolData{Protocol_Name: protocol}
	}

	// Create a new entry in the Hosts map if the host is not found
	if _, ok := connection.Hosts[host]; !ok {
		connection.Hosts[host] = &HostData{Host_Name: host}
	}

	// Update all network statistics as well as the time this connection was updated
	connection.Download += download
	connection.Upload += upload

	connection.Processes[pid].Download += download
	connection.Processes[pid].Upload += upload
	connection.Processes[pid].Update_Time = time.Now().UnixMilli()

	connection.Protocols[protocol].Download += download
	connection.Protocols[protocol].Upload += upload

	connection.Hosts[host].Download += download
	connection.Hosts[host].Upload += upload
}
