package f2b_test

import (
	"os"
	"testing"
	"time"

	"dnscount/ingest"
	"dnscount/ingest/f2b"
)

func TestFail2banLog(t *testing.T) {
	f, err := os.Open("../../testdata/fail2ban.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ports, err := f2b.ParsePorts("jellyfin=80,443,8096; sshd=ssh")
	if err != nil {
		t.Fatal(err)
	}
	var bans []ingest.Ban
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	var increases []ingest.Ban
	st, err := ingest.Run(f, &f2b.Fail2ban{Ports: ports}, now, func(r ingest.Record) error {
		if r.Ban.Event == "increase" {
			increases = append(increases, *r.Ban)
		} else {
			bans = append(bans, *r.Ban)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := (ingest.Stats{Lines: 20, Records: 11, Skipped: 8, Bad: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	est := time.FixedZone("", -5*3600)
	want := []ingest.Ban{
		{TS: time.Date(2026, 10, 27, 20, 22, 58, 0, est), Event: "ban", Jail: "jellyfin", IP: "203.0.113.9", Ports: "80,443,8096", Failures: 3},
		{TS: time.Date(2026, 10, 27, 21, 22, 58, 0, est), Event: "unban", Jail: "jellyfin", IP: "203.0.113.9", Ports: "80,443,8096"},
		{TS: time.Date(2026, 10, 27, 21, 30, 1, 0, est), Event: "ban", Jail: "caddy-probe", IP: "198.51.100.4", Failures: 2, BanTime: 48 * time.Hour},
		{TS: time.Date(2026, 10, 27, 22, 0, 0, 0, est), Event: "unban", Jail: "caddy-probe", IP: "198.51.100.4"},
		{TS: time.Date(2026, 10, 27, 22, 0, 5, 0, est), Event: "ban", Jail: "caddy-probe", IP: "198.51.100.4"},
		{TS: time.Date(2026, 10, 27, 22, 10, 0, 0, est), Event: "ban", Jail: "sshd", IP: "2001:db8::7", Ports: "ssh"},
		// fail2ban 1.1 order: the increase comes after the ban, so the store
		// applies it. It must not stick to the next, unrelated ban.
		{TS: time.Date(2026, 10, 27, 23, 28, 54, 0, est), Event: "ban", Jail: "caddy-probe", IP: "203.0.113.50"},
		{TS: time.Date(2026, 10, 27, 23, 40, 0, 0, est), Event: "unban", Jail: "caddy-probe", IP: "203.0.113.50"},
		{TS: time.Date(2026, 10, 27, 23, 50, 0, 0, est), Event: "ban", Jail: "caddy-probe", IP: "203.0.113.50"},
	}
	if len(increases) != 2 || increases[0].BanTime != 48*time.Hour || increases[1].BanTime != 36*time.Hour {
		t.Errorf("increases = %+v, want 2d and 1d12h", increases)
	}
	if len(bans) != len(want) {
		t.Fatalf("got %d bans: %+v", len(bans), bans)
	}
	for i, w := range want {
		b := bans[i]
		b.Hash = ""
		if !b.TS.Equal(w.TS) || b.Event != w.Event || b.Jail != w.Jail || b.IP != w.IP || b.Ports != w.Ports ||
			b.Failures != w.Failures || b.BanTime != w.BanTime {
			t.Errorf("ban %d = %+v\nwant     %+v", i, b, w)
		}
	}
}

func TestParsePortsRejectsJunk(t *testing.T) {
	if _, err := f2b.ParsePorts("jellyfin"); err == nil {
		t.Error("accepted a jail with no ports")
	}
}
