package main

import (
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	ps_host "github.com/shirou/gopsutil/v3/host"
	ps_net "github.com/shirou/gopsutil/v3/net"
	ps_process "github.com/shirou/gopsutil/v3/process"
)

// ActiveProcess stores all relevant information of a process generating network traffic, including the subprocesses, protocols used and external hosts.
type ActiveProcess struct {
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

// SocketConnectionPorts serves as a tuple for storing the local address port and remote address port.
// This is used as a key for mapping PIDs to the port used by the process
type SocketConnectionPorts struct {
	localAddressPort  uint32
	remoteAddressPort uint32
}

// SocketConnectionProcess stores relevant process information.
type SocketConnectionProcess struct {
	name         string
	pid          int32
	creationTime int64
}

// GetSocketConnections retrieves the system-wide socket connections made by active processes and stores them in a global map.
func GetSocketConnections(interval int16, getConnectionsMutex *sync.RWMutex) {
	var (
		connections             []ps_net.ConnectionStat // connections stores the scoket connections list from ps_net.Connections
		socketConnectionPorts   SocketConnectionPorts   // socketConnectionPorts stores the local and remote ports as keys for the connections2pid map
		socketConnectionProcess SocketConnectionProcess // socketConnectionProcess stores the relevant process information pertaining to that key

		pid          int32
		processName  string
		creationTime int64
		localAddr    string
		remoteAddr   string
		err          error
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
			pid = conn.Pid

			// Skip this iteration if either local or remote IPs don't exist
			if localAddr = conn.Laddr.IP; localAddr == "" {
				continue
			}

			if remoteAddr = conn.Raddr.IP; remoteAddr == "" {
				continue
			}

			// Get the process name and creation time; skip this iteration should any errors occur
			if creationTime, processName, err = GetProcessData(pid); err != nil {
				continue
			} else {
				socketConnectionProcess = SocketConnectionProcess{name: processName, pid: pid, creationTime: creationTime}
			}

			// Add the process information as an entry in the map, using both ports as the key
			socketConnectionPorts = SocketConnectionPorts{localAddressPort: conn.Laddr.Port, remoteAddressPort: conn.Raddr.Port}

			// Store this information in the connections2pid map
			getConnectionsMutex.Lock()
			connections2pid[socketConnectionPorts] = socketConnectionProcess
			getConnectionsMutex.Unlock()
		}

		time.Sleep(time.Second * time.Duration(interval))
	}
}

// ProcessPacket relates packet information to its related process.
// It stores the process information in an existing or new ActiveProcess and updates the ActiveProcesses map directly.
func ProcessPacket(decodedLayers []gopacket.LayerType, macs []string, payload int, getConnectionsMutex *sync.RWMutex) {
	var (
		key, invertedKey SocketConnectionPorts         // key and invertedKey stores the local and remote ports (or the inverse) as keys to the connections2pid map.
		isUpload         bool                  = false // Initializes a flag to indicate whether the packet flow is an upload or download.

		pid                      int32
		creationTime             int64
		processName              string
		srcHost, dstHost         string
		srcProtocol, dstProtocol string
		activeProcess            *ActiveProcess
	)

	// Iterate through the decoded layers, extracting relevant information.
	for _, layerType := range decodedLayers {
		switch layerType {
		// Determine whether the packet flow is an upload or download by comparing MAC addresses.
		case layers.LayerTypeEthernet:
			for _, localMac := range macs {
				if localMac == eth.DstMAC.String() {
					isUpload = true
					break
				}
			}

		// Get host information from the Network Layer.
		case layers.LayerTypeIPv4:
			if isUpload {
				dstHost = ipv4.SrcIP.String()
			} else {
				srcHost = ipv4.DstIP.String()
			}

		case layers.LayerTypeIPv6:
			if isUpload {
				dstHost = ipv6.SrcIP.String()
			} else {
				srcHost = ipv6.DstIP.String()
			}

		// Creates keys using the local and remote ports to check a process' existence in the connections2pid map.
		case layers.LayerTypeTCP:
			key = SocketConnectionPorts{localAddressPort: uint32(tcp.SrcPort), remoteAddressPort: uint32(tcp.DstPort)}
			invertedKey = SocketConnectionPorts{localAddressPort: uint32(tcp.DstPort), remoteAddressPort: uint32(tcp.SrcPort)}

			if isUpload {
				dstProtocol = tcp.SrcPort.String()
			} else {
				srcProtocol = tcp.DstPort.String()
			}

		case layers.LayerTypeUDP:
			key = SocketConnectionPorts{localAddressPort: uint32(udp.SrcPort), remoteAddressPort: uint32(udp.DstPort)}
			invertedKey = SocketConnectionPorts{localAddressPort: uint32(udp.DstPort), remoteAddressPort: uint32(udp.SrcPort)}

			if isUpload {
				dstProtocol = udp.SrcPort.String()
			} else {
				srcProtocol = udp.DstPort.String()
			}
		}
	}

	// Lock the connections2pid map.
	getConnectionsMutex.Lock()

	// Ensure its unlocked after this functions returns.
	defer getConnectionsMutex.Unlock()

	// Check if the process exist as a socket connection. If not, return.
	if connection, ok := connections2pid[key]; ok {
		processName = connection.name
		pid = connection.pid
		creationTime = connection.creationTime
	} else if connection, ok := connections2pid[invertedKey]; ok {
		pid = connection.pid
		creationTime = connection.creationTime
	} else {
		return
	}

	// Create a new ActiveProcess object for this process if one does not exist in the activeProcesses map
	if _, ok := activeProcesses[processName]; !ok {
		activeProcess = CreateActiveProcess(processName)
		activeProcesses[processName] = activeProcess
	}

	// Get the ActiveProcess information for this process
	activeProcess = activeProcesses[processName]

	// Update the ActiveProcess according to packet flow
	if isUpload {
		UpdateActiveProcess(activeProcess, creationTime, pid, dstHost, dstProtocol, 0, payload)
	} else {
		UpdateActiveProcess(activeProcess, creationTime, pid, srcHost, srcProtocol, payload, 0)
	}
}

// CreateActiveProcess creates a new ActiveProcess object, making empty maps where applicable. Returns a pointer to the new ActiveProcess
func CreateActiveProcess(name string) (activeProcess *ActiveProcess) {
	activeProcess = &ActiveProcess{Name: name}

	activeProcess.Processes = make(map[int32]*ProcessData)
	activeProcess.Protocols = make(map[string]*ProtocolData)
	activeProcess.Hosts = make(map[string]*HostData)

	return activeProcess
}

// UpdateActiveProcess updates an activeProcess with information extracted from the packet. This function updates the connection directly by reference.
func UpdateActiveProcess(activeProcess *ActiveProcess, creationTime int64, pid int32, host string, protocol string, download int, upload int) {
	// Create a new entry in the Processes map if the PID is not found
	if _, ok := activeProcess.Processes[pid]; !ok {
		activeProcess.Processes[pid] = &ProcessData{Pid: pid, Create_Time: creationTime}
	}

	// Create a new entry in the Protocols map if the protocol is not found
	if _, ok := activeProcess.Protocols[protocol]; !ok {
		activeProcess.Protocols[protocol] = &ProtocolData{Protocol_Name: protocol}
	}

	// Create a new entry in the Hosts map if the host is not found
	if _, ok := activeProcess.Hosts[host]; !ok {
		activeProcess.Hosts[host] = &HostData{Host_Name: host}
	}

	// Update all network statistics as well as the time this connection was updated
	activeProcess.Download += download
	activeProcess.Upload += upload

	activeProcess.Processes[pid].Download += download
	activeProcess.Processes[pid].Upload += upload
	activeProcess.Processes[pid].Update_Time = time.Now().UnixMilli()

	activeProcess.Protocols[protocol].Download += download
	activeProcess.Protocols[protocol].Upload += upload

	activeProcess.Hosts[host].Download += download
	activeProcess.Hosts[host].Upload += upload
}

// GetProcessData retrieves a process' name and creation time given its PID.
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
