package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// insertAlert stores an alert. Re-importing a line (same line_hash) adds
// nothing, except that it fills in the CEF context columns on a row stored
// before they existed: that's how the raw files backfill them.
const insertAlert = `INSERT INTO ids_alerts (ts, src_ip, src_port, dst_ip, dst_port, proto, action,
		signature, signature_id, category, severity, source,
		direction, src_name, src_mac, dst_name, dst_mac, policy, line_hash)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(line_hash) DO UPDATE SET direction = excluded.direction,
		src_name = excluded.src_name, src_mac = excluded.src_mac,
		dst_name = excluded.dst_name, dst_mac = excluded.dst_mac, policy = excluded.policy
	WHERE (ids_alerts.direction, ids_alerts.src_name, ids_alerts.src_mac,
	       ids_alerts.dst_name, ids_alerts.dst_mac, ids_alerts.policy) = ('','','','','','')
	  AND (excluded.direction, excluded.src_name, excluded.src_mac,
	       excluded.dst_name, excluded.dst_mac, excluded.policy) != ('','','','','','')`

// droppedColumns were never read. CREATE TABLE IF NOT EXISTS leaves an
// existing table alone, so dropColumns removes them from databases made
// before they went. Dropping a column rewrites its table once.
var droppedColumns = []struct{ table, column string }{
	{"dns_queries", "client_name"},
}

// enrichDroppedColumns are the same for the explorer's database.
var enrichDroppedColumns = []struct{ table, column string }{
	{"lan_clients", "first_seen"}, {"lan_clients", "last_seen"},
	{"feed_versions", "loaded_at"}, {"feed_versions", "entries"},
	{"ip_asn", "list_version"}, {"ip_asn", "updated_at"},
}

// dropColumns drops each column that's still there. Several dnscount
// processes open the database at boot, so another may drop one first:
// that's fine.
func dropColumns(db *sql.DB, cols []struct{ table, column string }) error {
	for _, c := range cols {
		have, err := hasColumn(db, c.table, c.column)
		if err != nil {
			return err
		}
		if !have {
			continue
		}
		_, err = db.Exec(`ALTER TABLE ` + c.table + ` DROP COLUMN ` + c.column)
		if err != nil && !strings.Contains(err.Error(), "no such column") {
			return fmt.Errorf("drop %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
