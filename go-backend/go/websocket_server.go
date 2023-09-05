package main

import (
	"encoding/json"
	"log"
	"net/http"

	"nhooyr.io/websocket"
)

var (
	proc_to_json chan []byte = make(chan []byte) // Channel used to send the JSON data to the websocket server
)

// jsonEncodeProcessData takes a ProcessData object, encodes it into JSON and sends it to the proc_to_json channel, where it will be sent to the Websocket client.
func jsonEncodeProcessData(process_data ProcessData) {
	if json_str, err := json.Marshal(process_data); err != nil {
		log.Println(err.Error())
	} else {
		proc_to_json <- json_str
	}
}

// websocketHandler opens the Websocket Server, waits for a connection and sends the 'proc_to_json' data
// TODO: Use InsecureSkipVerify ONLY for debugging. Use OriginPatterns to safely accept cross origin websockets
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

		data := <-proc_to_json

		if err := conn.Write(r.Context(), websocket.MessageText, data); err != nil {
			log.Printf("Failed to send message: %v", err)
			return
		}
	}
}

// startServer initializes the Websocket handle and assigns it to port 50000
func startServer() {
	log.Printf("Waiting for client connection on ws://localhost:50000/")
	http.HandleFunc("/", websocketHandler)
	http.ListenAndServe(":50000", nil)
}
