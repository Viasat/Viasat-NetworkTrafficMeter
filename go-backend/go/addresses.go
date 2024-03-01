package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// NetworkInterface stores relevant information from devices listed by pcap.FindAllDevs()
type NetworkInterface struct {
	Index       int
	Description string
	Name        string
}

// GetMacAddresses returns an array of physical hardware addresses for all devices listed in net.Interfaces().
func GetMacAddresses() (macs []string, err error) {
	if ifaces, err := net.Interfaces(); err != nil {
		return macs, err
	} else {
		for _, device := range ifaces {
			if device.HardwareAddr.String() != "" {
				macs = append(macs, device.HardwareAddr.String())
			}
		}
	}

	return macs, nil
}

// PrintUsage prints the usage instructions for the program
func PrintUsage() {
	fmt.Println("Usage: go run . -i <interface> [-f <filter> -v]")
	fmt.Println("-i <interface> - Network interface to capture packets on.")
	fmt.Println("-legacy - Legacy mode, where the interface must be chosen from the backend.")
	fmt.Println("List of available interfaces: ")
}

// GetInterface shows a list of network interfaces.
func GetInterfaceList() (netDevices []NetworkInterface, err error) {
	if devices, err := pcap.FindAllDevs(); err != nil {
		return netDevices, err
	} else {
		for i, dev := range devices {
			netDevices = append(netDevices, NetworkInterface{Index: i, Description: dev.Description, Name: dev.Name})
		}
	}
	return netDevices, nil
}

// GetInterfaceFromList shows a list of network interfaces for the user to choose should they not inform one (legacy mode).
func GetInterfaceFromList() (device string, err error) {
	if devices, err := GetInterfaceList(); err != nil {
		return "", err
	} else {
		for i, dev := range devices {
			fmt.Printf("%d - %s (NPF Device Address: %s)\n", i, dev.Description, dev.Name)
		}

		var index int

		fmt.Print("Select the index of the network interface you wish to monitor: ")

		if _, err := fmt.Scanf("%d", &index); err != nil {
			return "", err
		} else {
			if index < len(devices) && index >= 0 {
				return devices[index].Name, nil
			} else {
				return "", errors.New("Index not found")
			}
		}
	}
}

func GetIPs(networklayer gopacket.NetworkLayer)(string, string, error){
	var (
		srcIP  string
		destIP string
	)
	srcIP = networklayer.NetworkFlow().Src().String()
	destIP = networklayer.NetworkFlow().Dst().String()

	return srcIP, destIP, nil
}

func GetPorts(transportLayer gopacket.TransportLayer)(uint64, uint64, error){
	var (
		srcPort  uint64
		destPort uint64
		err      error
	)
	srcPortStr := transportLayer.TransportFlow().Src().String()
	destPortStr := transportLayer.TransportFlow().Dst().String()

	if srcPort, err = strconv.ParseUint(srcPortStr, 10, 32); err != nil {
		return 0, 0, err
	}
	if destPort, err = strconv.ParseUint(destPortStr, 10, 32); err != nil {
		return 0, 0, err
	}

	return srcPort, destPort, nil
}