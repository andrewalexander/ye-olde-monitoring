package store_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnscount/ingest"
	"dnscount/ingest/ids"
	"dnscount/store"
)

// ids_alerts as it shipped, before the CEF context columns.
const oldAlertsTable = `CREATE TABLE ids_alerts (
	id           INTEGER PRIMARY KEY,
	ts           TEXT    NOT NULL,
	src_ip       TEXT    NOT NULL,
	src_port     INTEGER NOT NULL DEFAULT 0,
	dst_ip       TEXT    NOT NULL DEFAULT '',
	dst_port     INTEGER NOT NULL DEFAULT 0,
	proto        TEXT    NOT NULL DEFAULT '',
	action       TEXT    NOT NULL,
	signature    TEXT    NOT NULL DEFAULT '',
	signature_id INTEGER NOT NULL DEFAULT 0,
	category     TEXT    NOT NULL DEFAULT '',
	severity     INTEGER NOT NULL DEFAULT 0,
	source       TEXT    NOT NULL,
	line_hash    TEXT    NOT NULL UNIQUE
)`

// An existing database gets the new columns on open, and re-importing the
// raw lines fills them in on the rows already there, without duplicates.
func TestAlertColumnsMigrateAndBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(oldAlertsTable); err != nil {
		t.Fatal(err)
	}
	// The first fixture line, stored the way the old code stored it.
	b, _ := os.ReadFile("../testdata/unifi-cef.log")
	first := strings.SplitN(string(b), "\n", 2)[0]
	hash := ingest.NewDeduper().Key(first)
	if _, err := old.Exec(`INSERT INTO ids_alerts (ts, src_ip, src_port, dst_port, proto, action, signature, signature_id,
		severity, source, line_hash) VALUES ('2026-11-03T15:03:25.230000000Z', '203.0.113.30', 52555, 443, 'tcp', 'blocked',
		'ET DROP Dshield Block Listed Source group 1', 2402000, 7, 'unifi-cef', ?)`, hash); err != nil {
		t.Fatal(err)
	}
	old.Close()

	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, err := st.Alerts(store.AlertFilter{})
	if err != nil || len(a) != 1 || a[0].Direction != "" {
		t.Fatalf("after migrate: %+v %v", a, err)
	}
	// Opening again is a no-op.
	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()

	// The backfill: the old row gains its context, the new line is added.
	if n := importFile(t, st, "unifi-cef.log", ids.UniFi{}); n != 2 {
		t.Errorf("backfill touched %d rows, want 2 (1 filled in, 1 new)", n)
	}
	a, _ = st.Alerts(store.AlertFilter{})
	if len(a) != 2 {
		t.Fatalf("%d alerts after backfill, want 2", len(a))
	}
	var filled store.Alert
	for _, x := range a {
		if x.SrcIP == "203.0.113.30" {
			filled = x
		}
	}
	if filled.Direction != "incoming" || filled.DstName != "media-server" || filled.DstMAC != "02:00:00:00:00:02" ||
		filled.Policy != "DShield Block List" || filled.Signature != "ET DROP Dshield Block Listed Source group 1" {
		t.Errorf("filled-in row: %+v", filled)
	}
	// And again: nothing more to do.
	if n := importFile(t, st, "unifi-cef.log", ids.UniFi{}); n != 0 {
		t.Errorf("second backfill touched %d rows", n)
	}
	// Grouping by the new columns works.
	if kv, err := st.TopAlerts("dst_name", store.AlertFilter{}); err != nil || len(kv) != 2 {
		t.Errorf("top by dst_name: %+v %v", kv, err)
	}
}
