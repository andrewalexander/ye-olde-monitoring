package store_test

import (
	"fmt"
	"testing"
	"time"

	"dnscount/hit"
	"dnscount/ingest"
	"dnscount/ingest/f2b"
	"dnscount/ingest/ids"
	"dnscount/store"
)

func addHits(t *testing.T, st *store.Store, ip, host string, at ...time.Time) {
	t.Helper()
	for i, ts := range at {
		h := hit.Hit{Hash: fmt.Sprintf("%s-%s-%d-%d", ip, host, ts.UnixNano(), i), TS: ts, Site: "jf", Source: "caddy",
			ClientIP: ip, Method: "GET", Host: host, Path: "/", Status: 404}
		if _, err := st.InsertHits([]hit.Hit{h}); err != nil {
			t.Fatal(err)
		}
	}
}

func ban(t *testing.T, st *store.Store, b ingest.Ban) {
	t.Helper()
	if err := st.InsertBan(b); err != nil {
		t.Fatal(err)
	}
}

func TestBansPairUnbansAndFindLeaks(t *testing.T) {
	st := open(t)
	t0 := now.Add(-3 * time.Hour)
	web := "80,443,8096"

	// 1. Held: hits before the ban and after the unban, none during.
	addHits(t, st, "203.0.113.1", "jellyfin.example", t0.Add(-time.Hour), t0.Add(-time.Minute), t0.Add(2*time.Hour))
	ban(t, st, ingest.Ban{TS: t0, Event: "ban", Jail: "caddy-probe", IP: "203.0.113.1", Ports: web, BanTime: 24 * time.Hour, Failures: 2})
	ban(t, st, ingest.Ban{TS: t0.Add(time.Hour), Event: "unban", Jail: "caddy-probe", IP: "203.0.113.1", Ports: web})

	// 2. Leaked: a request on 8096 half an hour into the ban. One finishing
	// inside the grace period doesn't count.
	addHits(t, st, "203.0.113.2", "192.168.1.10:8096", t0.Add(store.BanGrace/2), t0.Add(30*time.Minute))
	ban(t, st, ingest.Ban{TS: t0, Event: "ban", Jail: "caddy-404", IP: "203.0.113.2", Ports: web, BanTime: time.Hour})

	// 3. An sshd ban only covers port 22, so web hits during it aren't leaks.
	addHits(t, st, "203.0.113.3", "jellyfin.example", t0.Add(10*time.Minute))
	ban(t, st, ingest.Ban{TS: t0, Event: "ban", Jail: "sshd", IP: "203.0.113.3", Ports: "ssh", BanTime: time.Hour})

	bans, err := st.Bans(store.BanFilter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 3 {
		t.Fatalf("got %d bans, want 3: %+v", len(bans), bans)
	}
	by := map[string]store.Ban{}
	for _, b := range bans {
		by[b.IP] = b
	}
	if b := by["203.0.113.1"]; b.UnbannedAt.IsZero() || b.HitsBefore != 2 || b.HitsDuring != 0 || b.Failures != 2 || b.BanTime != 24*time.Hour {
		t.Errorf("held ban = %+v", b)
	}
	if b := by["203.0.113.2"]; !b.UnbannedAt.IsZero() || b.HitsDuring != 1 {
		t.Errorf("leaked ban (still in force) = %+v, want 1 hit during", b)
	}
	if b := by["203.0.113.3"]; b.HitsDuring != 0 {
		t.Errorf("sshd ban counted web hits as leaks: %+v", b)
	}

	if got, _ := st.Bans(store.BanFilter{Jail: "sshd"}, now); len(got) != 1 || got[0].IP != "203.0.113.3" {
		t.Errorf("jail filter = %+v", got)
	}
}

func TestInsertBanRejectsJunk(t *testing.T) {
	st := open(t)
	if err := st.InsertBan(ingest.Ban{TS: now, Event: "ban", Jail: "j", IP: "not-an-ip"}); err == nil {
		t.Error("accepted a non-IP")
	}
	if err := st.InsertBan(ingest.Ban{TS: now, Event: "kick", Jail: "j", IP: "203.0.113.1"}); err == nil {
		t.Error("accepted an unknown event")
	}
}

func TestAlerts(t *testing.T) {
	st := open(t)
	if n := importFile(t, st, "unifi-ids.log", ids.UniFi{}); n != 5 {
		t.Fatalf("imported %d alerts, want 5", n)
	}
	// Importing the same file again adds nothing.
	if n := importFile(t, st, "unifi-ids.log", ids.UniFi{}); n != 0 {
		t.Fatalf("re-import added %d", n)
	}
	addHits(t, st, "203.0.113.7", "jellyfin.example", now.Add(-time.Hour))

	all, err := st.Alerts(store.AlertFilter{Since: now.AddDate(-2, 0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("got %d alerts", len(all))
	}
	blocked, _ := st.Alerts(store.AlertFilter{Since: now.AddDate(-2, 0, 0), Action: "blocked"})
	if len(blocked) != 2 {
		t.Errorf("blocked = %+v", blocked)
	}
	mine, _ := st.Alerts(store.AlertFilter{Since: now.AddDate(-2, 0, 0), IP: "203.0.113.7"})
	if len(mine) != 1 || mine[0].SrcHits != 1 || mine[0].Signature != "ET SCAN Suspicious inbound to mySQL port 3306" {
		t.Errorf("by ip = %+v", mine)
	}
	top, err := st.TopAlerts("signature", store.AlertFilter{Since: now.AddDate(-2, 0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if len(top) == 0 || top[0].Key != "ET DROP Dshield Block Listed Source group 1" || top[0].Count != 2 {
		t.Errorf("top signatures = %+v", top)
	}
	if _, err := st.TopAlerts("src_ip; DROP TABLE hits", store.AlertFilter{}); err == nil {
		t.Error("accepted an unknown column")
	}
}

// fail2ban's own log, end to end: ban lengths land on the right bans whichever
// order fail2ban logs "Increase Ban" in, and re-reading changes nothing.
func TestBansFromFail2banLog(t *testing.T) {
	st := open(t)
	importFile(t, st, "fail2ban.log", &f2b.Fail2ban{})
	importFile(t, st, "fail2ban.log", &f2b.Fail2ban{})
	bans, err := st.Bans(store.BanFilter{Jail: "caddy-probe"}, now)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range bans {
		got = append(got, fmt.Sprintf("%s %s %v", b.BannedAt.Format("15:04"), b.IP, b.BanTime))
	}
	want := []string{
		"04:50 203.0.113.50 0s",      // a later ban: no increase logged for it
		"04:28 203.0.113.50 36h0m0s", // increase logged after the ban
		"03:00 198.51.100.4 0s",      // Restore Ban
		"02:30 198.51.100.4 48h0m0s", // increase logged before the ban
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("caddy-probe bans:\n got %q\nwant %q", got, want)
	}
}
