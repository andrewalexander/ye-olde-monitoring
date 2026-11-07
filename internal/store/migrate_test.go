package store_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/ids"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// A row stored before the CEF context columns were parsed gets them filled
// in when its raw line is imported again, without duplicates.
func TestAlertBackfill(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// The first fixture line, stored the way the old code stored it.
	b, _ := os.ReadFile("../testdata/unifi-cef.log")
	first := strings.SplitN(string(b), "\n", 2)[0]
	hash := ingest.NewDeduper().Key(first)
	if _, err := st.DB().Exec(`INSERT INTO ids_alerts (ts, src_ip, src_port, dst_port, proto, action, signature, signature_id,
		severity, source, line_hash) VALUES ('2026-11-03T15:03:25.230000000Z', '203.0.113.30', 52555, 443, 'tcp', 'blocked',
		'ET DROP Dshield Block Listed Source group 1', 2402000, 7, 'unifi-cef', ?)`, hash); err != nil {
		t.Fatal(err)
	}

	// The backfill: the old row gains its context, the new line is added.
	if n := importFile(t, st, "unifi-cef.log", ids.UniFi{}); n != 2 {
		t.Errorf("backfill touched %d rows, want 2 (1 filled in, 1 new)", n)
	}
	a, _ := st.Alerts(store.AlertFilter{})
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

// Databases made before the unread columns went lose them on open, and
// keep working.
func TestDropsUnusedColumns(t *testing.T) {
	dir := t.TempDir()
	main, enr := filepath.Join(dir, "dnscount.db"), filepath.Join(dir, "explore.db")
	for path, qs := range map[string][]string{
		main: {`CREATE TABLE dns_queries (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, client_ip TEXT NOT NULL,
			client_name TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL, qtype TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL, line_hash TEXT NOT NULL UNIQUE)`,
			`INSERT INTO dns_queries (ts, client_ip, domain, source, line_hash) VALUES ('2026-11-03T12:00:00Z', '192.168.1.20', 'a.example', 't', 'h0')`},
		enr: {`CREATE TABLE lan_clients (ip TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)`,
			`CREATE TABLE feed_versions (provider TEXT PRIMARY KEY, version TEXT NOT NULL, loaded_at TEXT NOT NULL, entries INTEGER NOT NULL)`,
			`CREATE TABLE ip_asn (ip TEXT PRIMARY KEY, asn INTEGER NOT NULL, as_owner TEXT NOT NULL DEFAULT '',
				country TEXT NOT NULL DEFAULT '', list_version TEXT NOT NULL, updated_at TEXT NOT NULL)`,
			`INSERT INTO lan_clients VALUES ('192.168.1.20', 'x', 'y')`},
	} {
		db, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range qs {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(q, err)
			}
		}
		db.Close()
	}
	st, err := store.Open(main)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e, err := store.OpenEnrich(enr)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cols := func(db *sql.DB, table string) string {
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			rows.Scan(&n)
			out = append(out, n)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		db          *sql.DB
		table, want string
	}{
		{st.DB(), "dns_queries", "id,ts,client_ip,domain,qtype,source,line_hash"},
		{e.DB(), "lan_clients", "ip"},
		{e.DB(), "feed_versions", "provider,version"},
		{e.DB(), "ip_asn", "ip,asn,as_owner,country"},
	} {
		if got := cols(c.db, c.table); got != c.want {
			t.Errorf("%s columns = %s, want %s", c.table, got, c.want)
		}
	}
	// The old rows are still there, and new ones go in.
	var n int
	st.DB().QueryRow(`SELECT count(*) FROM dns_queries`).Scan(&n)
	e.DB().QueryRow(`SELECT count(*) FROM lan_clients`).Scan(&n)
	if n != 1 {
		t.Errorf("lan_clients rows = %d", n)
	}
	if _, err := st.InsertRecords([]ingest.Record{{Query: &ingest.DNSQuery{Hash: "q1", TS: time.Now(), ClientIP: "192.168.1.21",
		Domain: "b.example", Source: "t"}}}); err != nil {
		t.Errorf("insert after drop: %v", err)
	}
	// Opening again is a no-op.
	st2, err := store.Open(main)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
}
