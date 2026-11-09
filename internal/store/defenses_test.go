package store_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// The Defenses list is every kind of event in one timeline, newest first,
// with the ones that didn't hold marked; firewall drops only when asked for.
func TestDefensesTimeline(t *testing.T) {
	st := open(t)
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return t0.Add(-d) }
	const (
		blocked = "198.51.100.10"
		leaky   = "198.51.100.11"
		tripper = "198.51.100.12"
		login   = "198.51.100.13"
		allowed = "198.51.100.14"
		dropped = "198.51.100.15"
	)
	if _, err := st.InsertRecords([]ingest.Record{
		{Alert: &ingest.IDSAlert{Hash: "a1", TS: at(time.Hour), SrcIP: blocked, DstIP: "192.0.2.1", DstPort: 22,
			Action: "blocked", Signature: "ET SCAN ssh", Category: "scan", Source: "unifi-cef"}},
		{Alert: &ingest.IDSAlert{Hash: "a2", TS: at(2 * time.Hour), SrcIP: allowed, DstIP: "192.0.2.1",
			Action: "allowed", Signature: "ET INFO probe", Source: "unifi-cef"}},
		{Auth: &ingest.AuthFailure{Hash: "l1", TS: at(3 * time.Hour), Source: "jellyfin", IP: login, User: "admin"}},
		{Conn: &ingest.Conn{Hash: "c1", TS: at(10 * time.Minute), ClientIP: dropped, DstIP: "192.0.2.1", DstPort: 23,
			Proto: "tcp", Action: "drop", Rule: "WAN_LOCAL-D-1", Source: "unifi-fw"}},
		{Conn: &ingest.Conn{Hash: "c2", TS: at(5 * time.Hour), ClientIP: leaky, DstIP: "192.0.2.1", DstPort: 443,
			Proto: "tcp", Action: "reject", Rule: "f2b-caddy", Source: "host-fw"}},
		{Conn: &ingest.Conn{Hash: "c3", TS: at(5 * time.Hour), ClientIP: dropped, Action: "accept", Source: "unifi-fw"}},
	}); err != nil {
		t.Fatal(err)
	}
	// A ban that leaked (a hit got through while it held), then fail2ban
	// restarting: an unban and the same ban restored straight after.
	ban(t, st, ingest.Ban{TS: at(6 * time.Hour), Event: "ban", Jail: "caddy", IP: leaky, Failures: 5, BanTime: time.Hour})
	addHits(t, st, leaky, "jellyfin.example", at(5*time.Hour+30*time.Minute))
	ban(t, st, ingest.Ban{TS: at(4 * time.Hour), Event: "unban", Jail: "caddy", IP: leaky})
	ban(t, st, ingest.Ban{TS: at(4*time.Hour - 10*time.Second), Event: "ban", Jail: "caddy", IP: leaky, Failures: 5})
	ban(t, st, ingest.Ban{TS: at(7 * time.Hour), Event: "ignored", Jail: "caddy", IP: "192.168.1.5"})
	if _, err := st.InsertTrip(store.Trip{TrippedAt: at(30 * time.Minute), CooldownUntil: t0, Breaker: "probe", Key: tripper,
		Reason: "bad lines", FirstSeen: at(time.Hour), Detail: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}

	type row struct{ kind, warn, ip string }
	rows := func(f store.DefenseFilter) []row {
		t.Helper()
		ev, err := st.Defenses(f, t0)
		if err != nil {
			t.Fatal(err)
		}
		var out []row
		for _, e := range ev {
			out = append(out, row{e.Kind, e.Warn, e.IP})
		}
		return out
	}
	day := at(24 * time.Hour)

	want := []row{
		{"trip", "", tripper},
		{"ids", "", blocked},
		{"ids", "allowed", allowed},
		{"login", "", login},
		{"ban", "", leaky}, // the restore: nothing reached a site after it
		{"ban", "leak", leaky},
	}
	if got := rows(store.DefenseFilter{Since: day}); !slices.Equal(got, want) {
		t.Errorf("default:\n got %v\nwant %v", got, want)
	}

	all := rows(store.DefenseFilter{Since: day, Kinds: []string{"all"}})
	if len(all) != 8 || all[0] != (row{"fw", "", dropped}) || !slices.Contains(all, row{"fw", "", leaky}) {
		t.Errorf("all: %v", all)
	}
	if got := rows(store.DefenseFilter{Since: day, Kinds: []string{"fw"}, IP: leaky}); !slices.Equal(got, []row{{"fw", "", leaky}}) {
		t.Errorf("fw for one address: %v", got)
	}
	if got := rows(store.DefenseFilter{Since: day, Kinds: []string{"allowed"}}); !slices.Equal(got, []row{{"ids", "allowed", allowed}}) {
		t.Errorf("allowed only: %v", got)
	}
	if got := rows(store.DefenseFilter{Since: day, IP: leaky}); len(got) != 2 {
		t.Errorf("one address: %v", got)
	}
	if got := rows(store.DefenseFilter{Since: day, Kinds: []string{"all"}, Limit: 3}); !slices.Equal(got, all[:3]) {
		t.Errorf("limit 3: %v, want %v", got, all[:3])
	}
	if got := rows(store.DefenseFilter{Since: at(45 * time.Minute)}); !slices.Equal(got, want[:1]) {
		t.Errorf("since 45m: %v", got)
	}

	ev, _ := st.Defenses(store.DefenseFilter{Since: day, Kinds: []string{"ban", "fw"}, IP: leaky}, t0)
	var what []string
	for _, e := range ev {
		what = append(what, e.What)
		if e.Kind == "ban" && e.ID == 0 {
			t.Errorf("ban without an id: %+v", e)
		}
	}
	if s := strings.Join(what, " | "); !strings.Contains(s, "caddy: 5 matches, for 1h, 1 got through") || !strings.Contains(s, "restored after a restart") ||
		!strings.Contains(s, "1 got through") || !strings.Contains(s, "rejected by this host while banned (f2b-caddy)") {
		t.Errorf("what: %s", s)
	}

	if _, err := st.Defenses(store.DefenseFilter{Kinds: []string{"nope"}}, t0); err == nil {
		t.Error("unknown kind accepted")
	}
}
