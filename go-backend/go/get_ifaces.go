package main

import (
	"log"
	"net"
	"strings"
)

type NetworkInterface struct {
	name        string
	description string
	mac_address string
	device_name string
}

// getMacAddresses returns a list of physical hardware addresses for all devices listed in net.Interfaces()
func getMacAddresses() (map[string]bool, error) {

	var (
		macs map[string]bool
		err  error = nil
	)

	if ifaces, e := net.Interfaces(); err != nil {
		log.Fatal(err)
		err = e
	} else {
		for _, device := range ifaces {
			if device.HardwareAddr.String() != "" {
				macs[strings.ToLower(device.HardwareAddr.String())] = true
			}
		}
	}

	return macs, err
}
