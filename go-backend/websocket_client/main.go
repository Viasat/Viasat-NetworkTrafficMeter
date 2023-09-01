package main

import (
	"context"
	"fmt"
	"log"

	"nhooyr.io/websocket"
)

// This script creates a client for connecting to the Websocket client.
// Used for debugging purposes, such as testing the connection and printing the received data
func main() {
	ctx := context.Background()
	url := "ws://localhost:50000"

	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer conn.Close(websocket.StatusInternalError, "Internal Server Error")

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
