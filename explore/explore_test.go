package explore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnscount/enrich"
	"dnscount/hit"
	"dnscount/ingest"
	"dnscount/store"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (*Explorer, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "dnscount.db")
	p, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	feeds := filepath.Join(dir, "feeds")
	os.MkdirAll(feeds, 0o755)
	f := enrich.Feed{Name: "bad", Kind: "ip", Format: "plain", Verdict: enrich.Malicious, Interval: time.Hour}
	os.WriteFile(f.File(feeds), []byte("203.0.113.66\n"), 0o644)
	x, err := Open(Config{DB: db, EnrichDB: filepath.Join(dir, "explore.db"), FeedsDir: feeds, Feeds: []enrich.Feed{f},
		Now: func() time.Time { return now }, QueryTimeout: 5 * time.Second,
		Sampler: &Sampler{ProcRoot: filepath.Join(dir, "proc"), CgroupRoot: filepath.Join(dir, "cg"), Units: []string{"dnscount-syslog"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	return x, p, dir
}

func get(t *testing.T, h http.Handler, path string) (*http.Response, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Result(), string(b)
}

func TestExplorerEndToEnd(t *testing.T) {
	x, p, _ := setup(t)
	evil := `/<script>alert(1)</script>`
	p.InsertHits([]hit.Hit{{Hash: "h1", TS: now.Add(-time.Hour), Site: "jf", Source: "caddy", ClientIP: "203.0.113.66",
		Path: evil, Status: 404}})
	p.InsertRecords([]ingest.Record{
		{Query: &ingest.DNSQuery{Hash: "q1", TS: now.Add(-time.Hour), ClientIP: "192.168.1.20", Domain: "evil.example.org", Source: "t"}},
		{Reply: &ingest.DNSReply{Hash: "r1", TS: now.Add(-time.Hour), Domain: "evil.example.org", Answer: "203.0.113.66", Status: "reply", Source: "t"}},
	})
	if err := x.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := x.Handler()

	resp, body := get(t, h, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "app.js") {
		t.Fatalf("GET / = %d %q", resp.StatusCode, body[:min(len(body), 80)])
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("CSP = %q", csp)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no nosniff")
	}
	if resp, _ := get(t, h, "/ui/vendor/tabulator.min.js"); resp.StatusCode != 200 {
		t.Errorf("tabulator: %d", resp.StatusCode)
	}

	for _, path := range []string{"/api/ips", "/api/domains", "/api/clients", "/api/flagged", "/api/feeds", "/api/overview",
		"/api/health", "/api/health/series", "/api/ip/203.0.113.66", "/api/domain/evil.example.org", "/api/hits",
		"/api/alerts", "/api/bans", "/api/trips", "/api"} {
		if resp, body := get(t, h, path); resp.StatusCode != 200 {
			t.Errorf("%s = %d: %s", path, resp.StatusCode, body)
		}
	}
	for _, path := range []string{"/api/ips?since=nope", "/api/ips?order=sideways", "/api/flagged?verdict=evil",
		"/api/ip/not-an-ip", "/api/hits?limit=x"} {
		if resp, _ := get(t, h, path); resp.StatusCode != 400 {
			t.Errorf("%s = %d, want 400", path, resp.StatusCode)
		}
	}

	// Attacker-controlled strings come back as JSON strings, never raw HTML.
	_, body = get(t, h, "/api/hits")
	if !strings.Contains(body, `"host_kind": ""`) {
		t.Errorf("hits lack host_kind: %s", body)
	}
	if resp, _ := get(t, h, "/api/hits?host_kind=sideways"); resp.StatusCode != 400 {
		t.Errorf("bad host_kind = %d", resp.StatusCode)
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "\\u003cscript\\u003e") {
		t.Errorf("hit path not escaped: %s", body)
	}

	_, body = get(t, h, "/api/flagged")
	var fl []struct {
		Indicator, Direction string
		Clients              []struct{ IP string }
		Verdict              string
	}
	json.Unmarshal([]byte(body), &fl)
	if len(fl) != 1 || fl[0].Indicator != "203.0.113.66" || fl[0].Direction != "both" || fl[0].Verdict != "malicious" ||
		len(fl[0].Clients) != 1 || fl[0].Clients[0].IP != "192.168.1.20" {
		t.Errorf("flagged = %s", body)
	}

	// A changed feed file is noticed and reconciled: the address drops off.
	f := x.cfg.Feeds[0]
	os.WriteFile(f.File(x.cfg.FeedsDir), []byte("198.51.100.1\n"), 0o644)
	os.Chtimes(f.File(x.cfg.FeedsDir), now.Add(time.Minute), now.Add(time.Minute))
	if err := x.ReloadFeeds(); err != nil {
		t.Fatal(err)
	}
	_, body = get(t, h, "/api/flagged")
	if strings.Contains(body, "203.0.113.66") {
		t.Errorf("still flagged after it left the list: %s", body)
	}
	_, body = get(t, h, "/api/ip/203.0.113.66")
	if !strings.Contains(body, `"removed_at"`) {
		t.Errorf("profile doesn't show the removal: %s", body)
	}
}

func TestSampler(t *testing.T) {
	dir := t.TempDir()
	proc, cg := filepath.Join(dir, "proc"), filepath.Join(dir, "cg")
	unit := filepath.Join(cg, "dnscount-syslog.service")
	os.MkdirAll(filepath.Join(proc, "pressure"), 0o755)
	os.MkdirAll(unit, 0o755)
	w := func(p, s string) { os.WriteFile(p, []byte(s), 0o644) }
	w(filepath.Join(proc, "pressure", "cpu"), "some avg10=1.50 avg60=0.10 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	w(filepath.Join(proc, "pressure", "io"), "some avg10=12.25 avg60=0 avg300=0 total=1\n")
	w(filepath.Join(proc, "loadavg"), "0.42 0.30 0.20 1/100 999\n")
	w(filepath.Join(proc, "meminfo"), "MemTotal: 8000 kB\nMemAvailable:   4000 kB\n")
	w(filepath.Join(unit, "memory.current"), "1048576\n")
	w(filepath.Join(unit, "cpu.stat"), "usage_usec 1000000\nuser_usec 1\n")
	w(filepath.Join(unit, "cpu.pressure"), "some avg10=3.00 avg60=0 avg300=0 total=0\n")
	db := filepath.Join(dir, "x.db")
	w(db, "x")
	w(db+"-wal", strings.Repeat("w", 4096))
	s := &Sampler{ProcRoot: proc, CgroupRoot: cg, DB: db, Units: []string{"dnscount-syslog", "dnscount-missing"}}

	s.Take(now)
	w(filepath.Join(unit, "cpu.stat"), "usage_usec 1500000\n")
	s.Observe("/api/ips", 30*time.Millisecond, 200, nil)
	s.Observe("/api/ips", 11*time.Second, 503, context.DeadlineExceeded)
	smp := s.Take(now.Add(10 * time.Second))
	if smp.WALBytes != 4096 || smp.PSI["cpu"] != 1.5 || smp.PSI["io"] != 12.25 || smp.Load1 != 0.42 || smp.MemAvailable != 4000*1024 {
		t.Errorf("system: %+v", smp)
	}
	if _, ok := smp.PSI["memory"]; ok {
		t.Error("missing pressure file read as a value")
	}
	u := smp.Units["dnscount-syslog"]
	if !u.Present || u.Mem != 1048576 || u.CPUPressure != 3 || u.CPU < 4.99 || u.CPU > 5.01 {
		t.Errorf("unit: %+v", u)
	}
	if smp.Units["dnscount-missing"].Present {
		t.Error("missing unit reported present")
	}
	if smp.Requests != 2 || smp.Timeouts != 1 || smp.QueryMax < 10000 {
		t.Errorf("queries: %+v", smp)
	}
	if sl := s.Slow(); len(sl) != 2 || sl[0].Took < sl[1].Took {
		t.Errorf("slow: %+v", sl)
	}
	// 24h ring.
	for i := 1; i <= 30; i++ {
		s.Take(now.Add(time.Duration(i) * time.Hour))
	}
	if all := s.Series(time.Time{}, 0); all[0].TS.Before(now.Add(6*time.Hour)) || len(all) > 25 {
		t.Errorf("ring kept %d samples from %v", len(all), all[0].TS)
	}
	if thin := s.Series(time.Time{}, 5); len(thin) > 5 {
		t.Errorf("thinned to %d", len(thin))
	}
}
