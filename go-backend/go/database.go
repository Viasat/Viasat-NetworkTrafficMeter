package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

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

func GetProcesses(db *sql.DB) (processData []ProcessData, err error) {
	selectQuery := `SELECT pd.pid, pd.create_time, pd.upload, pd.download FROM process_data AS pd`

	return queryProcesses(db, selectQuery)
}

// FIXME:
func GetProcessesByPid(db *sql.DB, pid int) (processData []ProcessData, err error) {
	selectQuery := `
	SELECT pd.pid, pd.create_time, pd.upload, pd.download FROM process_data AS pd WHERE pd.pid = ?
	`

	return queryProcesses(db, selectQuery, pid)
}

// FIXME:
func GetProcessesByTime(db *sql.DB, initialDate, endDate int64) (processData []ProcessData, err error) {
	selectQuery := `
	SELECT pd.pid, pd.create_time, pd.upload, pd.download 
	FROM process_data AS pd 
	INNER JOIN active_processes AS ap ON pd.active_process_id = ap.id
	WHERE ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryProcesses(db, selectQuery, initialDate, endDate)
}

// FIXME:
func GetProcessesByPidAndTime(db *sql.DB, pid int, initialDate, endDate int64) (processData []ProcessData, err error) {
	selectQuery := `
	SELECT pd.pid, pd.create_time, pd.upload, pd.download 
	FROM process_data AS pd 
	INNER JOIN active_processes AS ap ON pd.active_process_id = ap.id
	WHERE pd.pid = ? AND ap.update_time >= ? AND ap.update_time <= ?
	`

	return queryProcesses(db, selectQuery, pid, initialDate, endDate)
}

func queryActiveProcesses(db *sql.DB, query string, args ...interface{}) (activeProcesses []ActiveProcess, err error) {
	var (
		id   int
		rows *sql.Rows
	)

	// Run the first query, to select all active processes
	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			activeProcess ActiveProcess
		)

		if err = rows.Scan(
			&id,
			&activeProcess.Name,
			&activeProcess.Update_Time,
			&activeProcess.Upload,
			&activeProcess.Download); err != nil {
			return
		}

		activeProcess.Processes = make(map[int32]*ProcessData)
		activeProcess.Protocols = make(map[string]*ProtocolData)
		activeProcess.Hosts = make(map[string]*HostData)

		// Run a query to pick all processes from this active process
		subQuery := "SELECT pr.pid, pr.create_time, pr.upload, pr.download FROM process_data AS pr WHERE pr.active_process_id = ?"
		subRows, err := db.Query(subQuery, id)
		if err != nil {
			return activeProcesses, err
		}

		for subRows.Next() {
			var processData ProcessData
			if err = subRows.Scan(
				&processData.Pid,
				&processData.Create_Time,
				&processData.Upload,
				&processData.Download); err != nil {
				return activeProcesses, err
			}
			activeProcess.Processes[processData.Pid] = &processData
		}

		// Run a query to pick all protocols from this active process
		subQuery = "SELECT pr.protocol_name, pr.upload, pr.download FROM protocol_data AS pr WHERE pr.active_process_id = ?"
		subRows, err = db.Query(subQuery, id)
		if err != nil {
			return nil, err
		}

		for subRows.Next() {
			var protocolData ProtocolData
			if err = subRows.Scan(
				&protocolData.Protocol_Name,
				&protocolData.Upload,
				&protocolData.Download); err != nil {
				return nil, err
			}
			activeProcess.Protocols[protocolData.Protocol_Name] = &protocolData
		}
		// Run a query to pick all hosts from this active proces
		subQuery = "SELECT h.host_name, h.upload, h.download FROM host_data AS h WHERE h.active_process_id = ?"
		subRows, err = db.Query(subQuery, id)
		if err != nil {
			return nil, err
		}

		for subRows.Next() {
			var hostData HostData
			if err = subRows.Scan(
				&hostData.Host_Name,
				&hostData.Upload,
				&hostData.Download); err != nil {
				return nil, err
			}
			activeProcess.Hosts[hostData.Host_Name] = &hostData
		}

		activeProcesses = append(activeProcesses, activeProcess)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return activeProcesses, nil
}

func queryProcesses(db *sql.DB, query string, args ...interface{}) (processesData []ProcessData, err error) {
	var (
		rows *sql.Rows
	)

	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var processData ProcessData
		if err = rows.Scan(
			&processData.Pid,
			&processData.Create_Time,
			&processData.Upload,
			&processData.Download); err != nil {
			return
		}
		processesData = append(processesData, processData)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return processesData, nil
}
