package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

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

// StartWebserver initializes the Gin webserver on port 50000.
// It updates the "networkInterfaceChan" channel with the network interface name provided from a POST request to /devices.
func StartWebserver(db *sql.DB, bufferDatabaseMutex *sync.RWMutex, shutdownChan chan bool) {
	var (
		conn *websocket.Conn // conn represents a Websocket connection
		err  error           // err handles any function errors

		initialDateInt, endDateInt int64 // Variables for storing the data value as int
	)

	// Initialize the Gin engine with default options.
	// TODO: The default option for Gin is a debug version. Adjust accordingly to deploy for production.
	router := gin.Default()

	// Set the router's endpoints
	router.GET("/devices", GetDevices)             // Returns a list of all network interfaces

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

	router.GET("/statistics", func(c *gin.Context) { // Get total network throughput from the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all active processes by time
			if data, err := GetTotalThroughputByTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all active processes
			if data, err := GetTotalThroughput(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})

	router.GET("/active-processes", func(c *gin.Context) { // Get all ActiveProcesses on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all active processes by time
			if data, err := GetActiveProcessesByTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all active processes
			if data, err := GetActiveProcesses(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/active-processes/:name", func(c *gin.Context) { // Get all ActiveProcesses by name on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the active process' name from path parameters
		name := c.Param("name")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all active processes by name and time
			if data, err := GetActiveProcessByNameAndTime(db, name, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all active processes by name
			if data, err := GetActiveProcessByName(db, name); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/active-processes/statistics/:name", func(c *gin.Context) { // Get network throughput of a certain active process based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the active process' name from path parameters
		name := c.Param("name")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get active processes statistics by name and time
			if data, err := GetActiveProcessesThroughputByNameAndTime(db, name, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get active processes statistics by name
			if data, err := GetActiveProcessesThroughputByName(db, name); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/active-processes/statistics/entries", func(c *gin.Context) { // Get network throughput of active processes entries based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get active processes statistics by entry and time
			if data, err := GetActiveProcessesThroughputByEntryAndTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get active processes statistics by entry
			if data, err := GetActiveProcessesThroughputByEntry(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})

	router.GET("/processes", func(c *gin.Context) { // Get all Processes on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all processes by time
			if data, err := GetProcessesByTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all processes
			if data, err := GetProcesses(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/processes/:pid", func(c *gin.Context) { // Get all Processes by PID on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		var pidInt int // Variable for storing the PID's value as int

		// Get the PID value from path parameters
		pid := c.Param("pid")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		if pidInt, err = strconv.Atoi(pid); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for pid"})
		}

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all processes by pid and time
			if data, err := GetProcessesByPidAndTime(db, pidInt, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all processes by pid
			if data, err := GetProcessesByPid(db, pidInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/processes/statistics/:pid", func(c *gin.Context) { // Get network throughput of a certain process based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the active process' name from path parameters
		pid := c.Param("pid")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get processes statistics by PID and time
			if data, err := GetProcessesThroughputByPidAndTime(db, pid, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get processes statistics by PIDs
			if data, err := GetProcessesThroughputByPid(db, pid); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/processes/statistics/entries", func(c *gin.Context) { // Get network throughput of processes entries based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get processes statistics by entry and time
			if data, err := GetProcessesThroughputByEntryAndTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get processes statistics by entry
			if data, err := GetProcessesThroughputByEntry(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})

	router.GET("/protocols", func(c *gin.Context) { // Get all Protocols on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all protocols by time
			if data, err := GetProtocolsByTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all protocols
			if data, err := GetProtocols(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/protocols/:protocol", func(c *gin.Context) { // Get all Protocols by name on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the protocol name from the path parameters
		protocol := c.Param("protocol")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all protocols by name and time
			if data, err := GetProtocolsByNameAndTime(db, protocol, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all protocols by name
			if data, err := GetProtocolsByName(db, protocol); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/protocols/statistics/:name", func(c *gin.Context) { // Get network throughput of a certain protocol based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the active process' name from path parameters
		name := c.Param("name")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get protocols statistics by name and time
			if data, err := GetProtocolsThroughputByNameAndTime(db, name, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get protocols statistics by name
			if data, err := GetProtocolsThroughputByName(db, name); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/protocols/statistics/entries", func(c *gin.Context) { // Get network throughput of protocols entries based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get protocols statistics by entry and time
			if data, err := GetProtocolsThroughputByEntryAndTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get protocols statistics by entry
			if data, err := GetProtocolsThroughputByEntry(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})

	router.GET("/hosts", func(c *gin.Context) { // Get all Hosts on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all hosts by time
			if data, err := GetHostsByTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all hosts
			if data, err := GetHosts(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/hosts/:host", func(c *gin.Context) { // Get all Hosts by name on the database, or within a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the host name from path parameters
		host := c.Param("host")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get all hosts by name and time
			if data, err := GetHostsByNameAndTime(db, host, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get all hosts by name
			if data, err := GetHostsByName(db, host); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/hosts/statistics/:name", func(c *gin.Context) { // Get network throughput of a certain host based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the active process' name from path parameters
		name := c.Param("name")

		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get hosts statistics by name and time
			if data, err := GetHostsThroughputByNameAndTime(db, name, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get hosts statistics by name
			if data, err := GetHostsThroughputByName(db, name); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})
	router.GET("/hosts/statistics/entries", func(c *gin.Context) { // Get network throughput of host entries based (or not) on a timeframe
		SaveBufferToDatabase(db, bufferDatabaseMutex)
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Get hosts statistics by entry and time
			if data, err := GetHostsThroughputByEntryAndTime(db, initialDateInt, endDateInt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		} else {
			// Get hosts statistics by entry
			if data, err := GetHostsThroughputByEntry(db); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "No data available"})
			} else {
				c.JSON(http.StatusOK, data)
			}
		}
	})

	router.DELETE("/delete", func(c *gin.Context) { // Remove old entries from database, and free disk space
		// Get the dates in Unix Epoch from query parameters
		initialDate := c.DefaultQuery("initialDate", "")
		endDate := c.DefaultQuery("endDate", "")

		// Check which query to run, depending if the dates were provided
		if initialDate != "" && endDate != "" {
			// Convert the dates to int
			if initialDateInt, err = strconv.ParseInt(initialDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for initialDate"})
				return
			}

			if endDateInt, err = strconv.ParseInt(endDate, 10, 64); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect value for endDate"})
				return
			}

			// Remove entries based on time
			if err := RemoveEntries(db, initialDate, endDate); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "Entries deleted sucessfully"})
			}
		} else {
			// Remove entries
			if err := RemoveEntries(db); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "Entries deleted sucessfully"})
			}
		}

	})

	router.GET("/ping", func(c *gin.Context) { // Shutdown the server
		c.JSON(http.StatusOK, gin.H{"message": "Application is running"})
	})

	router.POST("/shutdown", func(c *gin.Context) { // Shutdown the server
		c.JSON(http.StatusOK, gin.H{"message": "Shuting down backend application"})
		shutdownChan <- true
	})

	// Run the server
	router.Run("localhost:50000")
}
