package main

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

// OpenDatabase opens the local database (or creates one if it doens't exist) and returns a database handle.
func OpenDatabase() (db *sql.DB, err error) {
	db, err = sql.Open("sqlite", "database.db")

	if err = createActiveProcessTable(db); err != nil {
		return nil, err
	}

	if err = createProcessDataTable(db); err != nil {
		return nil, err
	}

	if err = createProtocolDataTable(db); err != nil {
		return nil, err
	}

	if err = createHostDataTable(db); err != nil {
		return nil, err
	}

	return db, err
}

func createActiveProcessTable(db *sql.DB) (err error) {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS active_process (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		update_time INTEGER NOT NULL,
		upload INTEGER NOT NULL,
		download INTEGER NOT NULL
	);
	`

	_, err = db.Exec(createTableSQL)

	return err
}

func createProcessDataTable(db *sql.DB) (err error) {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS process_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pid INTEGER NOT NULL,
		create_time INTEGER NOT NULL,
		upload INTEGER NOT NULL,
		download INTEGER NOT NULL,
		active_process_id INTEGER NOT NULL,
		FOREIGN KEY (active_process_id) REFERENCES active_process (id)
	);
	`

	_, err = db.Exec(createTableSQL)

	return err
}

func createProtocolDataTable(db *sql.DB) (err error) {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS protocol_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		protocol_name TEXT NOT NULL,
		upload INTEGER NOT NULL,
		download INTEGER NOT NULL,
		active_process_id INTEGER NOT NULL,
		FOREIGN KEY (active_process_id) REFERENCES active_process (id)
	);
	`

	_, err = db.Exec(createTableSQL)

	return err
}

func createHostDataTable(db *sql.DB) (err error) {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS host_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_name TEXT NOT NULL,
		upload INTEGER NOT NULL,
		download INTEGER NOT NULL,
		active_process_id INTEGER NOT NULL,
		FOREIGN KEY (active_process_id) REFERENCES active_process (id)
	);
	`

	_, err = db.Exec(createTableSQL)

	return err
}

// InsertActiveProcessWithRelatedData saves the current activeProcesses buffer to the database.
func InsertActiveProcessWithRelatedData(db *sql.DB, activeProcesses map[string]*ActiveProcess) error {
	// Check if there any entries to save
	if len(activeProcesses) == 0 {
		return nil
	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, activeProcess := range activeProcesses {
		// Insert the ActiveProcess
		insertActiveProcessSQL := `
		INSERT INTO active_process (name, update_time, upload, download)
		VALUES (?, ?, ?, ?);
		`

		result, err := tx.Exec(insertActiveProcessSQL, activeProcess.Name, activeProcess.Update_Time, activeProcess.Upload, activeProcess.Download)
		if err != nil {
			return err
		}

		// Get the ID of the inserted ActiveProcess
		activeProcessID, err := result.LastInsertId()
		if err != nil {
			return err
		}

		// Insert related ProcessData records
		for _, processData := range activeProcess.Processes {
			insertProcessDataSQL := `
		INSERT INTO process_data (pid, create_time, upload, download, active_process_id)
		VALUES (?, ?, ?, ?, ?);
		`

			_, err := tx.Exec(insertProcessDataSQL, processData.Pid, processData.Create_Time, processData.Upload, processData.Download, activeProcessID)
			if err != nil {
				return err
			}
		}

		// Insert related ProtocolData records
		for _, protocolData := range activeProcess.Protocols {
			insertProtocolDataSQL := `
		INSERT INTO protocol_data (protocol_name, upload, download, active_process_id)
		VALUES (?, ?, ?, ?);
		`

			_, err := tx.Exec(insertProtocolDataSQL, protocolData.Protocol_Name, protocolData.Upload, protocolData.Download, activeProcessID)
			if err != nil {
				return err
			}
		}

		// Insert related HostData records
		for _, hostData := range activeProcess.Hosts {
			insertHostDataSQL := `
		INSERT INTO host_data (host_name, upload, download, active_process_id)
		VALUES (?, ?, ?, ?);
		`

			_, err := tx.Exec(insertHostDataSQL, hostData.Host_Name, hostData.Upload, hostData.Download, activeProcessID)
			if err != nil {
				return err
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func GetActiveProcesses(db *sql.DB) (activeProcesses []ActiveProcess, err error) {
	selectQuery := `SELECT * FROM active_process`

	return queryActiveProcesses(db, selectQuery)
}

func GetActiveProcessByName(db *sql.DB, name string) (activeProcesses []ActiveProcess, err error) {
	selectQuery := `
	SELECT * FROM active_process WHERE name = ?
	`

	return queryActiveProcesses(db, selectQuery, name)
}

func GetActiveProcessesByTime(db *sql.DB, initialDate, endDate int64) (activeProcesses []ActiveProcess, err error) {
	selectQuery := `
	SELECT * FROM active_process WHERE update_time >= ? AND update_time <= ?
	`

	return queryActiveProcesses(db, selectQuery, initialDate, endDate)
}

func GetActiveProcessByNameAndTime(db *sql.DB, name string, initialDate, endDate int64) (activeProcesses []ActiveProcess, err error) {
	selectQuery := `
	SELECT * FROM active_process WHERE name = ? AND update_time >= ? AND update_time <= ?
	`

	return queryActiveProcesses(db, selectQuery, name, initialDate, endDate)
}

// queryActiveProcesses is a helper function to execute queries related to ActiveProcesses.
// Specifically for ActiveProcesses, additional "subqueries" are executed in sequence in order to retrieve
// processes, hosts and protocols related to the activeProcess.
func queryActiveProcesses(db *sql.DB, query string, args ...interface{}) (activeProcesses []ActiveProcess, err error) {
	var (
		id   int       // id stores the unique id of an active_process entry from the database
		rows *sql.Rows // rows stores the fetched rows from the query
	)

	// Run the first query, to select all active processes
	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Iterate through all resulting rows
	for rows.Next() {
		// Create an ActiveProcess for each row
		var activeProcess ActiveProcess

		// Store the columns from the database in the ActiveProcess' attributes
		if err = rows.Scan(
			&id,
			&activeProcess.Name,
			&activeProcess.Update_Time,
			&activeProcess.Upload,
			&activeProcess.Download); err != nil {
			return
		}

		// Initialize the processes/protocols/hosts maps
		activeProcess.Processes = make(map[int32]*ProcessData)
		activeProcess.Protocols = make(map[string]*ProtocolData)
		activeProcess.Hosts = make(map[string]*HostData)

		// Run another query to pick all processes related to this ActiveProcess
		subQuery := "SELECT pr.pid, pr.create_time, pr.upload, pr.download FROM process_data AS pr WHERE pr.active_process_id = ?"
		subRows, err := db.Query(subQuery, id)
		if err != nil {
			return activeProcesses, err
		}

		// Iterate through all resulting rows
		for subRows.Next() {
			// Create a new ProcessData for each row
			var processData ProcessData

			// Store the columns from the database in the ProcessData's attributes
			if err = subRows.Scan(
				&processData.Pid,
				&processData.Create_Time,
				&processData.Upload,
				&processData.Download); err != nil {
				return activeProcesses, err
			}

			// Store the ProcessData in the ActiveProcess.Processes map
			activeProcess.Processes[processData.Pid] = &processData
		}

		// Run another query to pick all protocols from this active process
		subQuery = "SELECT pr.protocol_name, pr.upload, pr.download FROM protocol_data AS pr WHERE pr.active_process_id = ?"
		subRows, err = db.Query(subQuery, id)
		if err != nil {
			return nil, err
		}

		// Iterate through all resulting rows
		for subRows.Next() {
			// Create a new ProtocolData for each row
			var protocolData ProtocolData

			// Store the columns from the database in the ProtocolData's attributes
			if err = subRows.Scan(
				&protocolData.Protocol_Name,
				&protocolData.Upload,
				&protocolData.Download); err != nil {
				return nil, err
			}

			// Store the ProtocolData in the ActiveProcess.Protocols map
			activeProcess.Protocols[protocolData.Protocol_Name] = &protocolData
		}
		// Run a query to pick all hosts from this active process
		subQuery = "SELECT h.host_name, h.upload, h.download FROM host_data AS h WHERE h.active_process_id = ?"
		subRows, err = db.Query(subQuery, id)
		if err != nil {
			return nil, err
		}

		// Iterate through all resulting rows
		for subRows.Next() {
			// Create a new HostData for each row
			var hostData HostData

			// Store the columns from the database in the HostData's attributes
			if err = subRows.Scan(
				&hostData.Host_Name,
				&hostData.Upload,
				&hostData.Download); err != nil {
				return nil, err
			}

			// Store the ProtocolData in the ActiveProcess.Hosts map
			activeProcess.Hosts[hostData.Host_Name] = &hostData
		}

		// Append the ActiveProcess into the array
		activeProcesses = append(activeProcesses, activeProcess)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return activeProcesses, nil
}

func GetProcesses(db *sql.DB) (processData []ProcessData, err error) {
	selectQuery := `SELECT pd.pid, pd.create_time, pd.upload, pd.download FROM process_data AS pd`

	return queryProcesses(db, selectQuery)
}

func GetProcessesByPid(db *sql.DB, pid int) (processData []ProcessData, err error) {
	selectQuery := `
	SELECT pd.pid, pd.create_time, pd.upload, pd.download FROM process_data AS pd WHERE pd.pid = ?
	`

	return queryProcesses(db, selectQuery, pid)
}

func GetProcessesByTime(db *sql.DB, initialDate, endDate int64) (processData []ProcessData, err error) {
	selectQuery := `
	SELECT pd.pid, pd.create_time, pd.upload, pd.download 
	FROM process_data AS pd 
	INNER JOIN active_process AS ap ON pd.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryProcesses(db, selectQuery, initialDate, endDate)
}

func GetProcessesByPidAndTime(db *sql.DB, pid int, initialDate, endDate int64) (processData []ProcessData, err error) {
	selectQuery := `
	SELECT pd.pid, pd.create_time, pd.upload, pd.download 
	FROM process_data AS pd 
	INNER JOIN active_process AS ap ON pd.active_process_id = ap.id
	WHERE pd.pid = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryProcesses(db, selectQuery, pid, initialDate, endDate)
}

// queryProcesses is a helper function to execute queries related to Processes.
func queryProcesses(db *sql.DB, query string, args ...interface{}) (processesData []ProcessData, err error) {
	var (
		rows *sql.Rows
	)

	// Run the query to select all processes
	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Iterate through all resulting rows
	for rows.Next() {
		// Create a new ProcessData for each row
		var processData ProcessData

		// Store the columns from the database in the ProcessData's attributes
		if err = rows.Scan(
			&processData.Pid,
			&processData.Create_Time,
			&processData.Upload,
			&processData.Download); err != nil {
			return
		}

		// Append the ProcessData into the array
		processesData = append(processesData, processData)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return processesData, nil
}

func GetProtocols(db *sql.DB) (protocolData []ProtocolData, err error) {
	selectQuery := `SELECT prot.protocol_name, prot.upload, prot.download FROM protocol_data AS prot`

	return queryProtocols(db, selectQuery)
}

func GetProtocolsByName(db *sql.DB, protocol string) (protocolData []ProtocolData, err error) {
	selectQuery := `
	SELECT prot.protocol_name, prot.upload, prot.download FROM protocol_data AS prot WHERE prot.protocol_name = ?
	`

	return queryProtocols(db, selectQuery, protocol)
}

func GetProtocolsByTime(db *sql.DB, initialDate, endDate int64) (protocolData []ProtocolData, err error) {
	selectQuery := `
	SELECT prot.protocol_name, prot.upload, prot.download
	FROM protocol_data AS prot 
	INNER JOIN active_process AS ap ON prot.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryProtocols(db, selectQuery, initialDate, endDate)
}

func GetProtocolsByNameAndTime(db *sql.DB, protocol string, initialDate, endDate int64) (protocolData []ProtocolData, err error) {
	selectQuery := `
	SELECT prot.protocol_name, prot.upload, prot.download
	FROM protocol_data AS prot 
	INNER JOIN active_process AS ap ON prot.active_process_id = ap.id
	WHERE prot.protocol_name = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryProtocols(db, selectQuery, protocol, initialDate, endDate)
}

// queryProtocols is a helper function to execute queries related to Protocols.
func queryProtocols(db *sql.DB, query string, args ...interface{}) (protocolsData []ProtocolData, err error) {
	var (
		rows *sql.Rows
	)

	// Run the query to select all protocols
	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Iterate through all resulting rows
	for rows.Next() {
		// Create a new ProtocolData for each row
		var protocolData ProtocolData

		// Store the columns from the database in the ProtocolData's attributes
		if err = rows.Scan(
			&protocolData.Protocol_Name,
			&protocolData.Upload,
			&protocolData.Download); err != nil {
			return
		}

		// Append the ProtocolData into the array
		protocolsData = append(protocolsData, protocolData)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return protocolsData, nil
}

func GetHosts(db *sql.DB) (hostsData []HostData, err error) {
	selectQuery := `SELECT h.host_name, h.upload, h.download FROM host_data AS h`

	return queryHosts(db, selectQuery)
}

func GetHostsByName(db *sql.DB, protocol string) (hostsData []HostData, err error) {
	selectQuery := `
	SELECT h.host_name, h.upload, h.download FROM host_data AS h WHERE h.host_name = ?
	`

	return queryHosts(db, selectQuery, protocol)
}

func GetHostsByTime(db *sql.DB, initialDate, endDate int64) (hostsData []HostData, err error) {
	selectQuery := `
	SELECT h.host_name, h.upload, h.download
	FROM host_data AS h 
	INNER JOIN active_process AS ap ON h.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryHosts(db, selectQuery, initialDate, endDate)
}

func GetHostsByNameAndTime(db *sql.DB, protocol string, initialDate, endDate int64) (hostsData []HostData, err error) {
	selectQuery := `
	SELECT h.host_name, h.upload, h.download
	FROM host_data AS h 
	INNER JOIN active_process AS ap ON h.active_process_id = ap.id
	WHERE h.host_name = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryHosts(db, selectQuery, protocol, initialDate, endDate)
}

// queryHosts is a helper function to execute queries related to Hosts.
func queryHosts(db *sql.DB, query string, args ...interface{}) (hostsData []HostData, err error) {
	var (
		rows *sql.Rows
	)

	// Run the query to select all hosts
	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Iterate through all resulting rows
	for rows.Next() {
		// Create a new HostData for each row
		var hostData HostData

		// Store the columns from the database in the HostData's attributes
		if err = rows.Scan(
			&hostData.Host_Name,
			&hostData.Upload,
			&hostData.Download); err != nil {
			return
		}

		// Append the HostData into the array
		hostsData = append(hostsData, hostData)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return hostsData, nil
}

func GetTotalThroughput(db *sql.DB) (interface{}, error) {
	selectQuery := `
	SELECT SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM active_process
	`

	return queryStatistics(db, selectQuery)
}

func GetTotalThroughputByTime(db *sql.DB, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM active_process
	WHERE update_time >= ? AND update_time <= ?
	`

	return queryStatistics(db, selectQuery, initialDate, endDate)
}

func GetActiveProcessesThroughputByEntry(db *sql.DB) (interface{}, error) {
	selectQuery := `
	SELECT name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM active_process
	GROUP BY name
	`

	return queryNamedStatistics(db, selectQuery)
}

func GetActiveProcessesThroughputByName(db *sql.DB, name string) (interface{}, error) {
	selectQuery := `
	SELECT name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM active_process
	WHERE name = ?
	`

	return queryNamedStatistics(db, selectQuery, name)
}

func GetActiveProcessesThroughputByEntryAndTime(db *sql.DB, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM active_process
	WHERE update_time >= ? AND update_time <= ?
	GROUP BY name
	`
	return queryNamedStatistics(db, selectQuery, initialDate, endDate)
}

func GetActiveProcessesThroughputByNameAndTime(db *sql.DB, name string, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM active_process
	WHERE name = ? AND update_time >= ? AND update_time <= ?
	`
	return queryNamedStatistics(db, selectQuery, name, initialDate, endDate)
}

func GetProcessesThroughputByEntry(db *sql.DB) (interface{}, error) {
	selectQuery := `
	SELECT pid,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM process_data
	GROUP BY pid
	`

	return queryNamedStatistics(db, selectQuery)
}

func GetProcessesThroughputByPid(db *sql.DB, pid string) (interface{}, error) {
	selectQuery := `
	SELECT pid,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM process_data
	WHERE pid = ?
	`

	return queryNamedStatistics(db, selectQuery, pid)
}

func GetProcessesThroughputByEntryAndTime(db *sql.DB, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT p.pid,
	SUM(p.upload), 
	SUM(p.download), 
	SUM(p.upload+p.download) 
	FROM process_data AS p
	INNER JOIN active_process AS ap ON p.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	GROUP BY p.pid
	`
	return queryNamedStatistics(db, selectQuery, initialDate, endDate)
}

func GetProcessesThroughputByPidAndTime(db *sql.DB, pid string, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT p.pid,
	SUM(p.upload), 
	SUM(p.download), 
	SUM(p.upload+p.download)  
	FROM process_data AS p
	INNER JOIN active_process AS ap ON p.active_process_id = ap.id
	WHERE p.pid = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`
	return queryNamedStatistics(db, selectQuery, pid, initialDate, endDate)
}

func GetProtocolsThroughputByEntry(db *sql.DB) (interface{}, error) {
	selectQuery := `
	SELECT protocol_name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM protocol_data
	GROUP BY protocol_name
	`

	return queryNamedStatistics(db, selectQuery)
}

func GetProtocolsThroughputByName(db *sql.DB, name string) (interface{}, error) {
	selectQuery := `
	SELECT protocol_name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM protocol_data
	WHERE protocol_name = ?
	`

	return queryNamedStatistics(db, selectQuery, name)
}

func GetProtocolsThroughputByEntryAndTime(db *sql.DB, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT p.protocol_name,
	SUM(p.upload), 
	SUM(p.download), 
	SUM(p.upload+p.download) 
	FROM protocol_data AS p
	INNER JOIN active_process AS ap ON p.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	GROUP BY p.protocol_name
	`
	return queryNamedStatistics(db, selectQuery, initialDate, endDate)
}

func GetProtocolsThroughputByNameAndTime(db *sql.DB, pid string, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT p.protocol_name,
	SUM(p.upload), 
	SUM(p.download), 
	SUM(p.upload+p.download)  
	FROM protocol_data AS p
	INNER JOIN active_process AS ap ON p.active_process_id = ap.id
	WHERE p.protocol_name = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`
	return queryNamedStatistics(db, selectQuery, pid, initialDate, endDate)
}

func GetHostsThroughputByEntry(db *sql.DB) (interface{}, error) {
	selectQuery := `
	SELECT host_name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM host_data
	GROUP BY host_name
	`

	return queryNamedStatistics(db, selectQuery)
}

func GetHostsThroughputByName(db *sql.DB, name string) (interface{}, error) {
	selectQuery := `
	SELECT host_name,
	SUM(upload), 
	SUM(download), 
	SUM(upload+download) 
	FROM host_data
	WHERE host_name = ?
	`

	return queryNamedStatistics(db, selectQuery, name)
}

func GetHostsThroughputByEntryAndTime(db *sql.DB, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT h.host_name,
	SUM(h.upload), 
	SUM(h.download), 
	SUM(h.upload+h.download) 
	FROM host_data AS h
	INNER JOIN active_process AS ap ON h.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	GROUP BY h.host_name
	`
	return queryNamedStatistics(db, selectQuery, initialDate, endDate)
}

func GetHostsThroughputByNameAndTime(db *sql.DB, pid string, initialDate, endDate int64) (interface{}, error) {
	selectQuery := `
	SELECT h.host_name,
	SUM(h.upload), 
	SUM(h.download), 
	SUM(h.upload+h.download)  
	FROM host_data AS h
	INNER JOIN active_process AS ap ON h.active_process_id = ap.id
	WHERE h.host_name = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`
	return queryNamedStatistics(db, selectQuery, pid, initialDate, endDate)
}

func queryStatistics(db *sql.DB, query string, args ...interface{}) (interface{}, error) {
	type Statistics struct {
		Total_upload   int64 `json:"total_upload"`
		Total_download int64 `json:"total_download"`
		Total          int64 `json:"total"`
	}

	// Run the query to select all hosts
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats Statistics

	// Iterate through all resulting rows
	for rows.Next() {
		if err = rows.Scan(
			&stats.Total_upload,
			&stats.Total_download,
			&stats.Total); err != nil {
			return stats, err
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	log.Println(stats)

	return stats, nil
}

func queryNamedStatistics(db *sql.DB, query string, args ...interface{}) (map[string]interface{}, error) {
	type Statistics struct {
		Name           string `json:"name"`
		Total_upload   int64  `json:"total_upload"`
		Total_download int64  `json:"total_download"`
		Total          int64  `json:"total"`
	}

	// Run the query to select all hosts
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats map[string]interface{} = make(map[string]interface{})

	// Iterate through all resulting rows
	for rows.Next() {
		var statsEntry Statistics
		if err = rows.Scan(
			&statsEntry.Name,
			&statsEntry.Total_upload,
			&statsEntry.Total_download,
			&statsEntry.Total); err != nil {
			return nil, err
		}

		stats[statsEntry.Name] = statsEntry
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}
