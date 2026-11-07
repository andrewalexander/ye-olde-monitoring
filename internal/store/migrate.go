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

// addedColumns are columns added to tables after they first shipped.
// CREATE TABLE IF NOT EXISTS doesn't touch an existing table, so migrate adds
// them. Keep each one's declaration identical to schema.sql.
var addedColumns = []struct{ table, column, decl string }{
	{"ids_alerts", "direction", "TEXT NOT NULL DEFAULT ''"},
	{"ids_alerts", "src_name", "TEXT NOT NULL DEFAULT ''"},
	{"ids_alerts", "src_mac", "TEXT NOT NULL DEFAULT ''"},
	{"ids_alerts", "dst_name", "TEXT NOT NULL DEFAULT ''"},
	{"ids_alerts", "dst_mac", "TEXT NOT NULL DEFAULT ''"},
	{"ids_alerts", "policy", "TEXT NOT NULL DEFAULT ''"},
}

// droppedIndexes were replaced by wider ones in schema.sql (which runs
// first, so a lookup is never without an index).
var droppedIndexes = []string{"dns_replies_domain", "dns_replies_answer"}

// migrate adds any missing columns and drops replaced indexes. Several dnscount processes open the
// database at boot, so another may add a column first: that's fine.
func migrate(db *sql.DB) error {
	for _, ix := range droppedIndexes {
		if _, err := db.Exec(`DROP INDEX IF EXISTS ` + ix); err != nil {
			return fmt.Errorf("drop index %s: %w", ix, err)
		}
	}
	for _, c := range addedColumns {
		have, err := hasColumn(db, c.table, c.column)
		if err != nil {
			return err
		}
		if have {
			continue
		}
		_, err = db.Exec(`ALTER TABLE ` + c.table + ` ADD COLUMN ` + c.column + ` ` + c.decl)
		if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
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
