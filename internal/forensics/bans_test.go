package forensics

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/f2b"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

func TestBanForensics(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const scanner, exempt = "203.0.113.50", "192.168.1.2"
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	n := 0
	addHit := func(ip, path string, status int, at time.Time) {
		n++
		if _, err := st.InsertHits([]hit.Hit{{Hash: fmt.Sprint("h", n), TS: at, Site: "jf", Source: "caddy",
			ClientIP: ip, Method: "GET", Host: "jf.example", Path: path, Status: status}}); err != nil {
			t.Fatal(err)
		}
	}
	record := func(recs ...ingest.Record) {
		for i := range recs {
			n++
			if b := recs[i].Ban; b != nil {
				b.Hash = fmt.Sprint("b", n)
			}
			if c := recs[i].Conn; c != nil {
				c.Hash = fmt.Sprint("c", n)
			}
		}
		if _, err := st.InsertRecords(recs); err != nil {
			t.Fatal(err)
		}
	}

	// A day-old visit, a minute of probing, then the probe that bans it
	// (matched at whole seconds, as fail2ban logs it), and requests after.
	addHit(scanner, "/", 200, t0.Add(-24*time.Hour))
	for i := range 5 {
		addHit(scanner, fmt.Sprintf("/guess-%d", i), 404, t0.Add(-time.Minute+time.Duration(i)*10*time.Second))
	}
	addHit(scanner, "/.env", 404, t0.Add(-500*time.Millisecond))
	addHit(scanner, "/later", 404, t0.Add(time.Hour))
	record(ingest.Record{Ban: &ingest.Ban{TS: t0, Event: "ban", Jail: "caddy-probe-certain", IP: scanner,
		Ports: "80,443", Failures: 1, Found: []time.Time{t0.Add(-time.Second)}}})

	now := t0.Add(5 * time.Second)
	rec := &BanRecorder{St: st, Log: log.New(io.Discard, "", 0), Now: func() time.Time { return now },
		Settle: 15 * time.Second, Limits: map[string]f2b.Limit{"caddy-probe-certain": {MaxRetry: 1, FindTime: time.Hour}}}
	step := func() {
		t.Helper()
		if err := rec.Step(); err != nil {
			t.Fatal(err)
		}
	}
	detail := func(id int64) BanDetail {
		t.Helper()
		raw, err := st.BanDetail(id)
		if err != nil {
			t.Fatal(err)
		}
		var d BanDetail
		if raw != nil {
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}

	step()
	if d := detail(1); d.Event != "" {
		t.Fatalf("recorded before the access log could catch up: %+v", d)
	}
	now = t0.Add(30 * time.Second)
	step()
	d := detail(1)
	if d.Event != "ban" || d.Jail != "caddy-probe-certain" || d.MaxRetry != 1 || d.FindTime != 3600 || d.Backfilled {
		t.Errorf("header = %+v", d)
	}
	if d.Trigger == nil || len(d.Trigger.Hits) != 1 || d.Trigger.Hits[0].Path != "/.env" {
		t.Errorf("trigger = %+v, want the /.env request", d.Trigger)
	}
	if len(d.Samples) != 7 || d.Samples[0].Path != "/" || d.Samples[6].Path != "/.env" {
		t.Errorf("samples = %+v, want the 7 requests up to the ban, oldest first", d.Samples)
	}
	sum := 0
	for _, c := range d.RateCurve {
		sum += c
	}
	if len(d.RateCurve) != 10 || sum != 6 || d.RateCurve[9] != 6 {
		t.Errorf("rate curve = %v, want the 6 requests of the last hour in the last tenth", d.RateCurve)
	}
	if d.History == nil || d.History.Hits.Count != 7 || d.History.Bans != 0 {
		t.Errorf("history = %+v, want 7 hits and no bans before this one", d.History)
	}

	// Banned, it keeps knocking: the host logs the packets it rejects. Then
	// fail2ban unbans it.
	for i := range 3 {
		record(ingest.Record{Conn: &ingest.Conn{TS: t0.Add(time.Duration(i+1) * time.Minute), ClientIP: scanner,
			DstIP: "192.168.1.110", DstPort: 443, Proto: "tcp", Action: "reject", Rule: "f2b-caddy-probe-certain", Source: "host-fw"}})
	}
	record(ingest.Record{Conn: &ingest.Conn{TS: t0.Add(2 * time.Minute), ClientIP: scanner, DstIP: "192.168.1.110",
		DstPort: 443, Proto: "tcp", Action: "return", Rule: "WAN_IN-RET-30005", Source: "unifi-fw"}})
	unban := t0.Add(2 * time.Hour)
	record(ingest.Record{Ban: &ingest.Ban{TS: unban, Event: "unban", Jail: "caddy-probe-certain", IP: scanner, Ports: "80,443"}})
	now = unban.Add(5 * time.Second)
	step()
	if d := detail(1); d.During != nil {
		t.Fatalf("during recorded before the firewall log could catch up: %+v", d.During)
	}
	now = unban.Add(time.Minute)
	step()
	d = detail(1)
	if d.During == nil || d.During.Blocked != 3 || d.During.Ports[443] != 3 || len(d.During.Samples) != 3 ||
		d.During.RouterSeen != 1 || d.During.Leaked != 1 || !d.During.Until.Equal(unban) {
		t.Errorf("during = %+v, want 3 blocked on 443, 1 router line, and the /later request leaked", d.During)
	}

	// fail2ban restarting: unban, and the same ban restored seconds later.
	record(
		ingest.Record{Ban: &ingest.Ban{TS: unban.Add(time.Hour), Event: "ban", Jail: "caddy-probe", IP: scanner, Found: []time.Time{unban.Add(time.Hour)}}},
		ingest.Record{Ban: &ingest.Ban{TS: unban.Add(2 * time.Hour), Event: "unban", Jail: "caddy-probe", IP: scanner}},
		ingest.Record{Ban: &ingest.Ban{TS: unban.Add(2*time.Hour + 2*time.Second), Event: "ban", Jail: "caddy-probe", IP: scanner}},
	)
	// An exempt address fail2ban would have banned.
	addHit(exempt, "/.env", 404, unban.Add(3*time.Hour))
	record(ingest.Record{Ban: &ingest.Ban{TS: unban.Add(3 * time.Hour), Event: "ignored", Jail: "caddy-probe-certain", IP: exempt,
		Failures: 1, Found: []time.Time{unban.Add(3 * time.Hour)}}})
	// Recorded a day later: backfilled.
	now = unban.Add(27 * time.Hour)
	step()
	bans, err := st.Bans(store.BanFilter{IP: scanner, Jail: "caddy-probe"}, now)
	if err != nil || len(bans) != 2 || !bans[0].Restored {
		t.Fatalf("caddy-probe bans = %+v, %v", bans, err)
	}
	if r := detail(bans[0].ID); r.RestoredOf != bans[1].ID || r.Trigger != nil {
		t.Errorf("restore = %+v, want restored_of %d and no evidence of its own", r, bans[1].ID)
	}
	if o := detail(bans[1].ID); !o.Backfilled || o.History == nil || o.History.Bans != 1 {
		t.Errorf("backfilled ban = %+v, want backfilled with the earlier ban in its history", o)
	}
	ign, err := st.Bans(store.BanFilter{IP: exempt, Ignored: true}, now)
	if err != nil || len(ign) != 1 || !ign[0].Ignored || ign[0].HitsDuring != 0 {
		t.Fatalf("ignored = %+v, %v", ign, err)
	}
	if g := detail(ign[0].ID); g.Event != "ignored" || g.Trigger == nil || len(g.Trigger.Hits) != 1 {
		t.Errorf("ignored detail = %+v", g)
	}
	if real, _ := st.Bans(store.BanFilter{IP: exempt}, now); len(real) != 0 {
		t.Errorf("an ignored event listed as a ban: %+v", real)
	}
	if c, _ := st.BanCounts([]string{exempt}, time.Time{}); c[exempt] != 0 {
		t.Errorf("an ignored event counted as a ban: %v", c)
	}
	// Nothing left to do, and doing it again changes nothing.
	if p, _ := st.BansNeedingForensics(now, 10); len(p) != 0 {
		t.Errorf("still pending: %+v", p)
	}
}

func TestCurve(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	got := Curve([]time.Time{t0, t0.Add(59 * time.Second), t0.Add(9*time.Minute + 59*time.Second), t0.Add(10 * time.Minute)},
		t0, t0.Add(10*time.Minute), 10)
	if fmt.Sprint(got) != "[2 0 0 0 0 0 0 0 0 1]" {
		t.Errorf("curve = %v", got)
	}
}
