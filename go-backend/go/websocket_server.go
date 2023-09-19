package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

var (
	jsonData chan []byte = make(chan []byte) // Channel used to send the JSON data to the websocket server
)

// ParseActiveProcesses parse the activeProcesses data to JSON and sends it to the Websocket server.
/*
When the map has been encoded, this function sends a signal through the 'areProcessesEncoded' channel to the main function
to indicate that the activeProcesses map should be reset.
*/
func ParseActiveProcesses(activeProcesses *map[string]*ActiveProcess, areProcessesEncoded chan bool, activeProcessesMutex *sync.RWMutex) {
	for {
		activeProcessesMutex.Lock()
		// Encode the activeProcesses map to JSON, and log any errors
		if jsonStr, err := json.Marshal(*activeProcesses); err != nil {
			log.Println(err.Error())
		} else {
			// Blocking channel communication, so that this functions awaits for the websocket to send the previous data
			jsonData <- jsonStr

			// Non-blocking channel communication, so that it won't block the main function if packets aren't being received
			select {
			case areProcessesEncoded <- true:
			default:
			}
		}
		activeProcessesMutex.Unlock()

		time.Sleep(1 * time.Second)
	}
}

// WebsocketHandler opens the Websocket Server, waits for a connection and sends the 'jsonData' to the client
// FIXME: Use InsecureSkipVerify ONLY for debugging. Use OriginPatterns in the future to safely accept cross origin websockets
func websocketHandler(w http.ResponseWriter, r *http.Request) {

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	log.Printf("Connected to Websocket client")

	defer conn.Close(websocket.StatusInternalError, "Internal Server Error")

	for {

		data := <-jsonData

		if err := conn.Write(r.Context(), websocket.MessageText, data); err != nil {
			log.Printf("Failed to send message: %v", err)
			return
		}
	}
}

// StartServer initializes the Websocket handle and assigns it to port 50000
func StartServer() {
	log.Printf("Waiting for client connection on ws://localhost:50000/")
	http.HandleFunc("/", websocketHandler)
	http.ListenAndServe(":50000", nil)
}
