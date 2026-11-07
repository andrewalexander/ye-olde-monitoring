package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// The Domains list counts blocked replies for each row it returns. Without
// the partial index that reads every reply of a busy domain, and the page
// times out on a real database.
func TestBlockedCountUsesIndex(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.db.Query(`EXPLAIN QUERY PLAN `+blockedCount, "example.com", "2026-01-01T00:00:00Z")
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
	if got := strings.Join(plan, "; "); !strings.Contains(got, "dns_replies_blocked") {
		t.Errorf("plan = %q, want it to use dns_replies_blocked", got)
	}
}
