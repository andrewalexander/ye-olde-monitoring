package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/dns"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/fw"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

var now = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

func open(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func importFile(t *testing.T, st *store.Store, file string, p ingest.LineParser) int {
	t.Helper()
	f, err := os.Open("../testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []ingest.Record
	if _, err := ingest.Run(f, p, now, func(r ingest.Record) error { recs = append(recs, r); return nil }); err != nil {
		t.Fatal(err)
	}
	n, err := st.InsertRecords(recs)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func rowCounts(t *testing.T, st *store.Store) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, table := range []string{"hits", "dns_queries", "dns_replies", "connections", "counters"} {
		var n int
		if err := st.DB().QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

func TestReimportIsIdempotent(t *testing.T) {
	st := open(t)
	fixtures := []struct {
		file string
		p    ingest.LineParser
	}{
		{"dnsmasq.log", dns.Dnsmasq{}},
		{"pihole.log", dns.Dnsmasq{}},
		{"unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}}},
		{"adguard.json", dns.AdGuard{}},
		{"access-combined.log", ingest.Combined{Site: "www"}},
		{"access-caddy.log", ingest.Caddy{}},
	}
	for _, f := range fixtures {
		if n := importFile(t, st, f.file, f.p); n == 0 {
			t.Errorf("%s: first import inserted nothing", f.file)
		}
	}
	once := rowCounts(t, st)
	want := map[string]int{"hits": 7, "dns_queries": 7 + 3 + 1 + 2, "dns_replies": 7 + 2 + 1 + 2, "connections": 2, "counters": 0}
	for k, v := range want {
		if once[k] != v {
			t.Errorf("%s = %d after one import, want %d", k, once[k], v)
		}
	}
	for _, f := range fixtures {
		if n := importFile(t, st, f.file, f.p); n != 0 {
			t.Errorf("%s: re-import inserted %d new rows, want 0", f.file, n)
		}
	}
	twice := rowCounts(t, st)
	for k := range once {
		if once[k] != twice[k] {
			t.Errorf("%s: %d rows after one import, %d after two", k, once[k], twice[k])
		}
	}
}

func TestDNSCounts(t *testing.T) {
	st := open(t)
	importFile(t, st, "dnsmasq.log", dns.Dnsmasq{})
	got, err := st.DNSByDomain("example.com", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	at := func(h, m, s int) time.Time { return time.Date(2026, 10, 27, h, m, s, 0, time.UTC) }
	want := []store.ClientLookups{
		{ClientIP: "192.168.1.5", Seen: store.Seen{Count: 3, First: at(12, 0, 1), Last: at(12, 0, 5)}},
		{ClientIP: "192.168.1.7", Seen: store.Seen{Count: 1, First: at(13, 30, 0), Last: at(13, 30, 0)}},
		{ClientIP: "192.168.1.9", Seen: store.Seen{Count: 1, First: at(14, 0, 0), Last: at(14, 0, 0)}}, // www.example.com
	}
	if len(got) != len(want) {
		t.Fatalf("got %d clients, want %d: %+v (notexample.com must not match)", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.ClientIP != w.ClientIP || g.Count != w.Count || !g.First.Equal(w.First) || !g.Last.Equal(w.Last) {
			t.Errorf("row %d = %+v, want %+v", i, g, w)
		}
	}

	byClient, err := st.DNSByClient("192.168.1.5", time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, d := range byClient {
		counts[d.Domain] = d.Count
	}
	if len(counts) != 3 || counts["example.com"] != 3 || counts["ads.tracker.net"] != 1 || counts["notexample.com"] != 1 {
		t.Errorf("by client = %v", counts)
	}

	// since filters on time.
	later, _ := st.DNSByDomain("example.com", at(13, 0, 0))
	if len(later) != 2 {
		t.Errorf("since 13:00 got %d clients, want 2", len(later))
	}
}

func TestLookupThenConnect(t *testing.T) {
	st := open(t)
	importFile(t, st, "unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}})
	conns, err := st.ConnsForDomain("evil.example.org", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 || conns[0].ClientIP != "192.168.1.20" || conns[0].DstPort != 443 || conns[0].Count != 1 {
		t.Errorf("conns = %+v", conns)
	}
}

func TestCounterOnlyBumpsForNewHits(t *testing.T) {
	st := open(t)
	h := hit.Hit{Hash: "a", TS: now, Site: "s", Source: "test", ClientIP: "10.0.0.1", Count: true}
	for range 3 { // same hit three times (a retried batch)
		if _, err := st.InsertHits([]hit.Hit{h}); err != nil {
			t.Fatal(err)
		}
	}
	h2 := h
	h2.Hash, h2.Count = "b", false
	st.InsertHits([]hit.Hit{h2})
	if n, _ := st.Counter("s"); n != 1 {
		t.Errorf("counter = %d, want 1", n)
	}
	if n, _ := st.Counter("other"); n != 0 {
		t.Errorf("unknown site counter = %d, want 0", n)
	}
}

func TestCheck(t *testing.T) {
	st := open(t)
	importFile(t, st, "dnsmasq.log", dns.Dnsmasq{})
	importFile(t, st, "access-combined.log", ingest.Combined{Site: "www"})
	if problems, err := st.Check(now); err != nil || len(problems) != 0 {
		t.Fatalf("clean data: problems=%v err=%v", problems, err)
	}
	db := st.DB()
	db.Exec(`INSERT INTO dns_queries (ts, client_ip, domain, source, line_hash) VALUES ('2099-01-01T00:00:00.000000000Z', 'nope', 'Bad.', 'x', 'h1')`)
	db.Exec(`INSERT INTO hits (ts, site, source, client_ip, status, line_hash) VALUES ('1999-01-01T00:00:00.000000000Z', 'www', 'x', '', 999, 'h2')`)
	db.Exec(`INSERT INTO counters (site, count) VALUES ('ghost', 5)`)
	problems, err := st.Check(now)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"1 hits with empty client_ip",
		"1 hits with status outside 100-599",
		"1 dns_queries with uppercase or trailing-dot domain",
		"1 counters higher than the hits recorded for their site",
		"1 hits timestamped before 2000",
		"1 dns_queries timestamped in the future",
		"1 dns_queries with invalid client_ip",
	}
	have := map[string]bool{}
	for _, p := range problems {
		have[p] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("missing problem %q in %v", w, problems)
		}
	}
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Time{
		"":                     {},
		"24h":                  now.Add(-24 * time.Hour),
		"7d":                   now.AddDate(0, 0, -7),
		"2026-10-01T00:00:00Z": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	} {
		got, err := store.ParseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := store.ParseSince("yesterday", now); err == nil {
		t.Error("want error for nonsense")
	}
}

func TestBackup(t *testing.T) {
	st := open(t)
	importFile(t, st, "dnsmasq.log", dns.Dnsmasq{})
	dest := filepath.Join(t.TempDir(), "copy.db")
	if err := st.Backup(dest); err != nil {
		t.Fatal(err)
	}
	cp, err := store.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if a, b := rowCounts(t, st), rowCounts(t, cp); a["dns_queries"] != b["dns_queries"] || b["dns_queries"] != 7 {
		t.Errorf("backup has %v, original %v", b, a)
	}
}

func TestGroupRanks(t *testing.T) {
	st := open(t)
	at := func(h int) time.Time { return time.Date(2026, 10, 27, h, 0, 0, 0, time.UTC) }
	line := func(h int, client, domain string) ingest.Record {
		return ingest.Record{Query: &ingest.DNSQuery{Hash: domain + client + at(h).String(), TS: at(h), ClientIP: client, Domain: domain, QType: "A", Source: "test"}}
	}
	web := func(id string, h int, ip, path string) ingest.Record {
		return ingest.Record{Hit: &hit.Hit{Hash: id, TS: at(h), Site: "s", Source: "test", ClientIP: ip, Method: "GET", Path: path, Status: 200}}
	}
	if _, err := st.InsertRecords([]ingest.Record{
		line(1, "10.0.0.1", "common.test"), line(2, "10.0.0.1", "common.test"), line(9, "10.0.0.2", "common.test"),
		line(3, "10.0.0.1", "rare.test"),
		line(8, "10.0.0.2", "fresh.test"), line(9, "10.0.0.3", "fresh.test"),
		web("a", 1, "10.0.0.1", "/mine"), web("b", 2, "10.0.0.1", "/mine"), web("c", 3, "10.0.0.2", "/theirs"),
	}); err != nil {
		t.Fatal(err)
	}
	keys := func(kvs []store.KV) string {
		var out []string
		for _, kv := range kvs {
			out = append(out, kv.Key)
		}
		return strings.Join(out, ",")
	}
	dnsCase := func(name, want string, q store.GroupQuery) {
		t.Helper()
		q.By = "domain"
		got, err := st.DNSTop(q)
		if err != nil {
			t.Fatal(err)
		}
		if keys(got) != want {
			t.Errorf("%s = %q, want %q", name, keys(got), want)
		}
	}
	dnsCase("top", "common.test,fresh.test,rare.test", store.GroupQuery{Rank: store.RankTop})
	dnsCase("default is top", "common.test,fresh.test,rare.test", store.GroupQuery{})
	dnsCase("bottom", "rare.test,fresh.test,common.test", store.GroupQuery{Rank: store.RankBottom})
	dnsCase("limit", "rare.test", store.GroupQuery{Rank: store.RankBottom, Limit: 1})
	// common.test was looked up inside the window too, but it isn't new.
	dnsCase("new", "fresh.test", store.GroupQuery{Rank: store.RankNew, Since: at(5)})
	dnsCase("new, newest first", "fresh.test,rare.test", store.GroupQuery{Rank: store.RankNew, Since: at(3)})

	got, err := st.DNSTop(store.GroupQuery{By: "domain", Rank: store.RankNew, Since: at(5)})
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	// All of its lookups count, and First says when it appeared.
	if got[0].Count != 2 || !got[0].First.Equal(at(8)) {
		t.Errorf("new row = %+v", got[0])
	}
	top, _ := st.DNSTop(store.GroupQuery{By: "domain"})
	if !top[0].First.IsZero() {
		t.Errorf("top row has a first time: %+v", top[0])
	}

	byIP, err := st.TopHits(store.GroupQuery{By: "path", IP: "10.0.0.1"})
	if err != nil || keys(byIP) != "/mine" {
		t.Errorf("-top path -ip = %v %v", byIP, err)
	}

	// The first column is ranked, and the rest only label its rows: 10.0.0.2 has
	// the fewest hits, so it's first even though 10.0.0.1 has a rarer combination.
	if _, err := st.InsertRecords([]ingest.Record{
		web("d", 4, "10.0.0.1", "/once"), web("e", 4, "10.0.0.3", "/x"), web("f", 5, "10.0.0.3", "/y"),
		web("g", 6, "10.0.0.3", "/z"), web("h", 7, "10.0.0.3", "/z"),
	}); err != nil {
		t.Fatal(err)
	}
	multi, err := st.TopHits(store.GroupQuery{By: "ip,path", Rank: store.RankBottom})
	if err != nil {
		t.Fatal(err)
	}
	if want := "10.0.0.2\t/theirs,10.0.0.1\t/mine,10.0.0.1\t/once,10.0.0.3\t/z,10.0.0.3\t/x,10.0.0.3\t/y"; keys(multi) != want {
		t.Errorf("-bottom ip,path = %q, want %q", keys(multi), want)
	}
	if m := multi[1]; m.Count != 2 || m.Total != 3 || m.Keys[0] != "10.0.0.1" || m.Keys[1] != "/mine" {
		t.Errorf("row = %+v", m)
	}
	busiest, err := st.TopHits(store.GroupQuery{By: "ip,path"})
	if err != nil || !strings.HasPrefix(keys(busiest), "10.0.0.3\t/z,") {
		t.Errorf("-top ip,path = %q %v", keys(busiest), err)
	}
	// status is an integer column, so it has to come back as text too.
	mixed, err := st.TopHits(store.GroupQuery{By: "status,method", IP: "10.0.0.2"})
	if err != nil || len(mixed) != 1 || mixed[0].Key != "200\tGET" {
		t.Errorf("-top status,method = %+v %v", mixed, err)
	}
	// New goes by the first column too: fresh.test appeared at 8, and the new
	// client at 9 doesn't make it new again.
	newMulti, err := st.DNSTop(store.GroupQuery{By: "domain,client", Rank: store.RankNew, Since: at(5)})
	if err != nil {
		t.Fatal(err)
	}
	if keys(newMulti) != "fresh.test\t10.0.0.2,fresh.test\t10.0.0.3" || !newMulti[0].First.Equal(at(8)) {
		t.Errorf("-new domain,client = %q", keys(newMulti))
	}
	none, err := st.DNSTop(store.GroupQuery{By: "domain,client", Rank: store.RankNew, Since: at(9)})
	if err != nil || len(none) != 0 {
		t.Errorf("nothing's domain is new since 9: %q %v", keys(none), err)
	}

	// Status filters both forms of the report, by code or by class.
	if _, err := st.InsertRecords([]ingest.Record{
		{Hit: &hit.Hit{Hash: "n1", TS: at(1), Site: "s", Source: "test", ClientIP: "10.0.0.9", Method: "GET", Path: "/missing", Status: 404}},
		{Hit: &hit.Hit{Hash: "n2", TS: at(1), Site: "s", Source: "test", ClientIP: "10.0.0.9", Method: "GET", Path: "/denied", Status: 403}},
	}); err != nil {
		t.Fatal(err)
	}
	for status, want := range map[string]string{"404": "/missing", "4xx": "/denied,/missing"} {
		got, err := st.TopHits(store.GroupQuery{By: "path", Status: status, Rank: store.RankBottom})
		if err != nil || keys(got) != want {
			t.Errorf("status %s = %q %v, want %q", status, keys(got), err, want)
		}
	}
	listed, err := st.Hits(store.HitFilter{Status: "404"})
	if err != nil || len(listed) != 1 || listed[0].Path != "/missing" {
		t.Errorf("list status 404 = %+v %v", listed, err)
	}

	var bad store.BadQueryError
	if _, err := st.TopHits(store.GroupQuery{By: "password"}); !errors.As(err, &bad) {
		t.Errorf("bad by = %v", err)
	}
	for _, status := range []string{"abc", "9xx", "99", "1000", "4x"} {
		if _, err := st.TopHits(store.GroupQuery{By: "ip", Status: status}); !errors.As(err, &bad) {
			t.Errorf("status %q = %v", status, err)
		}
		if _, err := st.Hits(store.HitFilter{Status: status}); !errors.As(err, &bad) {
			t.Errorf("list status %q = %v", status, err)
		}
	}
	if _, err := st.TopHits(store.GroupQuery{By: "ip,password"}); !errors.As(err, &bad) {
		t.Errorf("bad by in a list = %v", err)
	}
	if _, err := st.DNSTop(store.GroupQuery{By: "domain", Rank: "sideways"}); !errors.As(err, &bad) {
		t.Errorf("bad rank = %v", err)
	}
}
