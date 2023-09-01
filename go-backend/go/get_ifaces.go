package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

type NetworkInterface struct {
	name        string
	description string
	mac_address string
	device_name string
}

// getMacAddresses returns a list of physical hardware addresses for all devices listed in net.Interfaces()
func getMacAddresses() (map[string]bool, error) {
	var macs map[string]bool = map[string]bool{}
	if ifaces, err := net.Interfaces(); err != nil {
		return macs, err
	} else {
		for _, device := range ifaces {
			if device.HardwareAddr.String() != "" {
				macs[strings.ToLower(device.HardwareAddr.String())] = true
			}
		}
	}

	return macs, nil
}

// printUsageAndDevices prints the usage instructions for the program as well as a list of network interfaces for the user to choose should they not inform one.
func printUsageAndDevices() (device string, err error) {
	fmt.Println("Usage: main -i <interface> [-f <filter> -v]")
	fmt.Println("-i <interface> - Network interface to capture packets on.")
	fmt.Println("-f <filter> - BPF filter")
	fmt.Println("-v - Verbose, set it to true for detailed information on the packet processing")
	fmt.Println()

	fmt.Println("List of available interfaces: ")

	if devices, err := pcap.FindAllDevs(); err != nil {
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
