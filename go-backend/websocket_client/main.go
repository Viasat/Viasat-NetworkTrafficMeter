package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"nhooyr.io/websocket"
)

type NetworkInterface struct {
	Index       int
	Description string
	Name        string
}

// This script creates a client for connecting to the Websocket client.
// Used for debugging purposes, such as testing the connection and printing the received data
func main() {
	// Define command-line flag for legacy mode
	legacyMode := flag.Bool("legacy", false, "Legacy mode, where the interface must be chosen from the backend.")

	// Parse command-line arguments
	flag.Parse()

	// Set websocket client parameters
	ctx := context.Background()
	url := "ws://localhost:50000"

	// Connect to websocket server
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer conn.Close(websocket.StatusInternalError, "Internal Server Error")

	// If not on legacy mode, get the interfaces from the backend and show them on console
	if !*legacyMode {
		// Get list of interfaces from server
		var options []NetworkInterface
		_, data, err := conn.Read(ctx)

		if err != nil {
			log.Fatal(err)
		}

		// Decode the incoming JSON into a list of Network Interfaces
		if err := json.Unmarshal(data, &options); err != nil {
			log.Println(err)
		}

		// Show available interfaces
		for i, opt := range options {
			fmt.Printf("%d - %s (NPF Device Address: %s)\n", i, opt.Description, opt.Name)
		}

		// Initialize variables used for processing the client's input
		var index int
		var selectedOption NetworkInterface

		// Read user's choice
		fmt.Print("Select the index of the network interface you wish to monitor: ")
		if _, err := fmt.Scanf("%d", &index); err != nil {
			log.Fatal(err)
		}

		// Check if the interface is valid, and store it into 'selectedOption'
		if index < len(options) && index >= 0 {
			selectedOption = options[index]
		} else {
			log.Fatal("Invalid option.")
		}

		// Parse the selected option into JSON
		if data, err = json.Marshal(selectedOption); err != nil {
			log.Println(err)
		}

		// Send the interface choice to server
		if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
			log.Printf("Failed to send message: %v", err)
			return
		}
	}

	// Print the network traffic in the console
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			log.Printf("Failed to read message: %v", err)
			return
		}

		if err != nil {
			log.Printf("Failed to unmarshal message: %v", err)
			return
		}

		fmt.Printf("Received: %s\n", string(data))
	}
}
