package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// planOf is SQLite's query plan for q on an empty database with the schema.
func planOf(t *testing.T, q string, args ...any) string {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.db.Query(`EXPLAIN QUERY PLAN `+q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	return strings.Join(plan, "; ")
}

// The Domains list counts blocked replies for each row it returns. Without
// the partial index that reads every reply of a busy domain, and the page
// times out on a real database.
func TestBlockedCountUsesIndex(t *testing.T) {
	if got := planOf(t, blockedCount, "example.com", "2026-01-01T00:00:00Z"); !strings.Contains(got, "dns_replies_blocked") {
		t.Errorf("plan = %q, want it to use dns_replies_blocked", got)
	}
}

// The Inbound IPs list reads each source over the window. Each has to go
// through its time index: a scan of the whole table grows with history and
// would eventually push the page past its deadline.
func TestInboundWindowsUseTimeIndexes(t *testing.T) {
	for q, index := range map[string]string{
		inboundHits:   "hits_ts",
		inboundAlerts: "ids_alerts_ts",
		inboundTrips:  "breaker_trips_tripped_at",
		inboundLogins: "auth_failures_ts",
		inboundDrops:  "connections_dropped",
	} {
		if got := planOf(t, q, "2026-01-01T00:00:00Z"); !strings.Contains(got, index) {
			t.Errorf("plan for %.40q… = %q, want it to use %s", q, got, index)
		}
	}
}

// The Defenses list reads each source newest first over the window, all
// addresses or one, through an index. Over everyone the index order is the
// answer's order, so there's no sort of the window either.
func TestDefenseWindowsUseIndexes(t *testing.T) {
	const since, until = "2026-01-01T00:00:00Z", "9999"
	for _, c := range []struct {
		q     string
		args  []any
		index string
		sorts bool // one address's rows are few; sorting them is fine
	}{
		{authFailuresAll, []any{since, until, 100}, "auth_failures_ts", false},
		{authFailuresFor, []any{"203.0.113.1", since, until, 100}, "auth_failures_ip", true},
		{defenseDrops, []any{since, 100}, "connections_dropped", false},
		{defenseDropsFor, []any{since, "203.0.113.1", 100}, "connections_client_ip", true},
	} {
		got := planOf(t, c.q, c.args...)
		if !strings.Contains(got, c.index) || !c.sorts && strings.Contains(got, "TEMP B-TREE") {
			t.Errorf("plan for %.40q… = %q, want it to use %s", c.q, got, c.index)
		}
	}
}
