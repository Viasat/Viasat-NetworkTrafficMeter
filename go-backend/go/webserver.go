package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"nhooyr.io/websocket"
)

var (
	jsonData chan []byte = make(chan []byte) // Channel used to send the JSON data to the websocket server
)

// GetDevices returns a list of all network interfaces
func GetDevices(c *gin.Context) {
	if ifaces, err := GetInterfaceList(); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Unable to retrieve interfaces"})
	} else {
		c.JSON(http.StatusOK, ifaces)
	}
}

// ParseActiveProcesses parse the activeProcesses data to JSON and sends it to the Websocket server.
func ParseActiveProcesses(activeProcessesChan <-chan map[string]*ActiveProcess) {
	for {
		// Encode the activeProcesses map to JSON, and log any errors
		if jsonStr, err := json.Marshal(<-activeProcessesChan); err != nil {
			log.Println(err.Error())
		} else {
			// Blocking channel communication, so that this functions awaits for the websocket to send the previous data
			jsonData <- jsonStr
		}
	}
}

// WebsocketHandler opens the Websocket Server, waits for a connection and sends the 'jsonData' to the client
// FIXME: Use InsecureSkipVerify ONLY for debugging. Use OriginPatterns in the future to safely accept cross origin websockets
func WebsocketHandlerLegacy(w http.ResponseWriter, r *http.Request) {

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
func StartServerLegacy(ifaceName chan<- string, legacyMode *bool) {
	var (
		conn          *websocket.Conn
		ifaces        []NetworkInterface
		data          []byte
		selectedIface NetworkInterface
		err           error
	)

	log.Printf("Waiting for client connection on ws://localhost:50000/")

	if *legacyMode {
		http.HandleFunc("/", WebsocketHandlerLegacy)
	} else {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Upgrades the HTTP connection to a WS connection
			if conn, err = websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}); err != nil {
				log.Fatal(err)
			}

			defer conn.Close(websocket.StatusInternalError, "Internal Server Error")

			log.Printf("Connected to Websocket client")

			// Get the list of available network interfaces
			if ifaces, err = GetInterfaceList(); err != nil {
				log.Fatal(err)
			}

			// Parse the list to JSON
			if data, err = json.Marshal(ifaces); err != nil {
				log.Fatal(err)
			}

			// Send the list to the client
			if err = conn.Write(r.Context(), websocket.MessageText, data); err != nil {
				log.Fatal(err)
			}

			// Wait for client response
			if _, data, err := conn.Read(r.Context()); err != nil {
				log.Fatal(err)
			} else {
				if err = json.Unmarshal(data, &selectedIface); err != nil {
					log.Fatal(err)
				}
			}

			// Send the selected interface to main to open the pcap handle
			ifaceName <- selectedIface.Name

			// Send the network traffic to client
			for {
				data := <-jsonData
				if err := conn.Write(r.Context(), websocket.MessageText, data); err != nil {
					log.Printf("Failed to send message: %v", err)
					return
				}
			}
		})
	}

	http.ListenAndServe(":50000", nil)
}

// StartWebserver initializes the Gin webserver on port 50000. It updates the "networkInterfaceChan" channel with the network interface name provided from a POST request to /devices.
func StartWebserver(networkInterfaceChan chan<- string) {
	var (
		conn *websocket.Conn // conn represents a Websocket connection
		err  error           // err handles any function errors
	)

	// Initialize the Gin engine with default options.
	// TODO: The default option for Gin is a debug version. Adjust accordingly to deploy for production.
	router := gin.Default()

	// Set the router's endpoints
	router.GET("/devices", GetDevices)             // Returns a list of all network interfaces
	router.POST("/devices", func(c *gin.Context) { // Set the desired network interface

		// Get network device's name from the request's body
		networkInterface := c.PostForm("interface")

		// Check if the interface exists. If it does, send its name to the channel and return OK. If not, return error
		if ifaces, err := GetInterfaceList(); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Unable to retrieve interfaces"})
		} else {
			for _, iface := range ifaces {
				if iface.Name == networkInterface {
					networkInterfaceChan <- networkInterface
					c.JSON(http.StatusOK, gin.H{"message": "Device set"})

					return
				}
			}
		}

		c.JSON(http.StatusNotFound, gin.H{"error": "Unable to locate device"})
	})
	router.GET("/ws", func(c *gin.Context) { // Websocket for supplying the client with current connections
		// Upgrades the HTTP connection to a WS connection
		if conn, err = websocket.Accept(c.Writer, c.Request, &websocket.AcceptOptions{InsecureSkipVerify: true}); err != nil {
			log.Fatal(err)
		}

		// Ensure the connection is closed should any errors occur
		defer conn.Close(websocket.StatusInternalError, "Internal Server Error")

		log.Printf("Connected to Websocket")

		// Send data to the client
		for {
			data := <-jsonData
			if err := conn.Write(c, websocket.MessageText, data); err != nil {
				log.Printf("Failed to send message: %v", err)
				return
			}
		}

	})

	// Run the server
	router.Run("localhost:50000")
}
