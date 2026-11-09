package store_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/enrich"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/dns"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/fw"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/ids"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// explorer is a primary database plus the explorer's two handles on it.
type explorer struct {
	primary, enr, ro *store.Store
}

func openExplorer(t *testing.T) explorer {
	t.Helper()
	dir := t.TempDir()
	p, err := store.Open(filepath.Join(dir, "dnscount.db"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := store.OpenEnrich(filepath.Join(dir, "explore.db"))
	if err != nil {
		t.Fatal(err)
	}
	ro, err := store.OpenReadOnly(filepath.Join(dir, "dnscount.db"), filepath.Join(dir, "explore.db"), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close(); e.Close(); p.Close() })
	return explorer{p, e, ro}
}

func (x explorer) index(t *testing.T) {
	t.Helper()
	if _, err := store.IndexNew(x.ro, x.enr, 2); err != nil { // tiny batches, to exercise the cursor
		t.Fatal(err)
	}
}

func list(t *testing.T, name, format, verdict, body string) *enrich.List {
	t.Helper()
	l, err := enrich.ParseList(enrich.Feed{Name: name, Format: format, Kind: "ip", Verdict: verdict, Interval: time.Hour}, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func asnTable(t *testing.T, rows string) *enrich.ASNTable {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(rows))
	w.Close()
	tab, err := enrich.ParseASN(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestReadOnlyNeverWrites(t *testing.T) {
	x := openExplorer(t)
	addHits(t, x.primary, "203.0.113.9", "jf.example", now)
	if _, err := x.ro.DB().Exec(`INSERT INTO hits (ts, site, source, client_ip, line_hash) VALUES ('t', 'x', 'x', '10.0.0.1', 'ro')`); err == nil {
		t.Fatal("wrote to the primary through the read-only handle")
	}
	if _, err := x.ro.DB().Exec(`INSERT INTO enrich.cursors (tbl, last_id) VALUES ('x', 1)`); err == nil {
		t.Fatal("wrote to explore.db through the read-only handle")
	}
	if _, err := x.enr.DB().Exec(`INSERT INTO cursors (tbl, last_id) VALUES ('x', 1)`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := x.ro.DB().QueryRow(`SELECT count(*) FROM enrich.cursors`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("read-only handle doesn't see explore.db writes: %d %v", n, err)
	}

	// A reader holding a snapshot open doesn't make the writer wait.
	tx, err := x.ro.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var before int
	tx.QueryRow(`SELECT count(*) FROM hits`).Scan(&before)
	start := time.Now()
	addHits(t, x.primary, "203.0.113.10", "jf.example", now, now.Add(time.Second))
	if d := time.Since(start); d > time.Second {
		t.Errorf("insert waited %v behind a reader", d)
	}
	var during int
	tx.QueryRow(`SELECT count(*) FROM hits`).Scan(&during)
	tx.Rollback()
	if during != before {
		t.Errorf("reader's snapshot changed under it: %d -> %d", before, during)
	}
	var after int
	x.ro.DB().QueryRow(`SELECT count(*) FROM hits`).Scan(&after)
	if after != before+2 {
		t.Errorf("new reads don't see the writes: %d", after)
	}

	// A cancelled context stops a query.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := x.ro.WithContext(ctx).Hits(store.HitFilter{}); err == nil {
		t.Error("query ran under a cancelled context")
	}
}

func enrichmentRow(t *testing.T, st *store.Store, provider, ind string) (listed bool, first, removed, detail, version string, ok bool) {
	t.Helper()
	err := st.DB().QueryRow(`SELECT current, first_seen, ended_at, coalesce(json_extract(facts, '$.detail'), ''), version
		FROM enrichment WHERE provider = ? AND indicator = ?`, provider, ind).Scan(&listed, &first, &removed, &detail, &version)
	return listed, first, removed, detail, version, err == nil
}

func TestReconcileTracksListChanges(t *testing.T) {
	x := openExplorer(t)
	importFile(t, x.primary, "unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}})
	importFile(t, x.primary, "unifi-ids.log", ids.UniFi{})
	x.index(t)

	var lan int
	x.enr.DB().QueryRow(`SELECT count(*) FROM lan_clients WHERE ip = '192.168.1.20'`).Scan(&lan)
	if lan != 1 {
		t.Error("192.168.1.20 not recorded as a LAN client")
	}
	var roles int
	if err := x.enr.DB().QueryRow(`SELECT roles FROM indicators WHERE indicator = '203.0.113.66'`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != store.RoleAnswer|store.RoleConn {
		t.Errorf("203.0.113.66 roles = %b", roles)
	}
	for _, private := range []string{"192.168.1.20", "192.168.1.10", "192.0.2.1"} {
		var n int
		x.enr.DB().QueryRow(`SELECT count(*) FROM indicators WHERE indicator = ?`, private).Scan(&n)
		if n != 0 && private != "192.0.2.1" {
			t.Errorf("private address %s indexed", private)
		}
	}
	// Re-indexing reads nothing new.
	if n, _ := store.IndexNew(x.ro, x.enr, 100); n != 0 {
		t.Errorf("second index read %d rows", n)
	}

	other := list(t, "other", "plain", enrich.Suspicious, "203.0.113.7\n")
	if _, err := x.enr.Reconcile(other, now.AddDate(0, 0, -90), now); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, otherVer, _ := enrichmentRow(t, x.enr, "feed:other", "203.0.113.7")

	t1, t2, t3 := now, now.Add(time.Hour), now.Add(2*time.Hour)
	since := now.AddDate(0, 0, -90)
	v1 := list(t, "drop", "spamhaus", enrich.Malicious, `{"cidr":"203.0.113.66/32","sblid":"SBL1"}`)
	if st, err := x.enr.Reconcile(v1, since, t1); err != nil || st.Added != 1 {
		t.Fatalf("v1: %+v %v", st, err)
	}
	v2 := list(t, "drop", "spamhaus", enrich.Malicious, `{"cidr":"203.0.113.7/32","sblid":"SBL2"}`)
	if st, err := x.enr.Reconcile(v2, since, t2); err != nil || st.Added != 1 || st.Removed != 1 {
		t.Fatalf("v2: %+v %v", st, err)
	}
	if listed, _, removed, _, _, _ := enrichmentRow(t, x.enr, "feed:drop", "203.0.113.66"); listed || removed == "" {
		t.Errorf("A after v2: listed %v removed %q", listed, removed)
	}
	// B appeared on the list after the alert that put it in the index.
	if listed, _, _, _, _, ok := enrichmentRow(t, x.enr, "feed:drop", "203.0.113.7"); !ok || !listed {
		t.Error("B not flagged retroactively")
	}
	v3 := list(t, "drop", "spamhaus", enrich.Malicious, `{"cidr":"203.0.113.0/24","sblid":"SBL3"}`)
	if _, err := x.enr.Reconcile(v3, since, t3); err != nil {
		t.Fatal(err)
	}
	listed, first, removed, detail, version, _ := enrichmentRow(t, x.enr, "feed:drop", "203.0.113.66")
	if !listed || removed != "" || detail != "SBL3" || version != v3.Version || !strings.HasPrefix(first, t1.Format("2006-01-02T15")) {
		t.Errorf("A after v3: listed %v first %s removed %q detail %s version %s", listed, first, removed, detail, version)
	}
	if out, err := x.enr.OutdatedRows(since); err != nil || len(out) != 0 {
		t.Errorf("outdated rows after reconcile: %v %v", out, err)
	}
	if _, _, _, _, v, _ := enrichmentRow(t, x.enr, "feed:other", "203.0.113.7"); v != otherVer {
		t.Error("reconciling one list touched another")
	}
}

func TestFlaggedInAndOut(t *testing.T) {
	x := openExplorer(t)
	importFile(t, x.primary, "unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}})
	importFile(t, x.primary, "unifi-ids.log", ids.UniFi{})
	// The same address also requested a probe path from our site.
	addHits(t, x.primary, "203.0.113.66", "jf.example", now.Add(-time.Hour))
	// A LAN device with a global IPv6 address hits the site too: never public.
	x.primary.InsertRecords([]ingest.Record{{Query: &ingest.DNSQuery{Hash: "v6q", TS: now, ClientIP: "2606:4700:4700::5",
		Domain: "example.net", Source: "test"}}})
	x.primary.InsertHits([]hit.Hit{{Hash: "v6h", TS: now, Site: "jf", Source: "caddy", ClientIP: "2606:4700:4700::5", Status: 200}})
	x.index(t)

	ls := store.Lists{
		Lists: []*enrich.List{
			list(t, "bad", "plain", enrich.Malicious, "203.0.113.66\n2606:4700:4700::5\n"),
			func() *enrich.List {
				l, _ := enrich.ParseList(enrich.Feed{Name: "tif", Format: "plain", Kind: "domain", Verdict: enrich.Malicious}, []byte("example.org\n"))
				return l
			}(),
		},
		ASN: asnTable(t, "203.0.113.0\t203.0.113.255\t64500\tNL\tEXAMPLE-AS\n"),
	}
	if _, err := x.enr.MatchNew(ls, now); err != nil {
		t.Fatal(err)
	}
	since := now.AddDate(0, 0, -30)

	fl, err := x.ro.Flagged(store.FlaggedQuery{Since: since})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.FlaggedRow{}
	for _, r := range fl {
		got[r.Indicator] = r
	}
	if _, ok := got["2606:4700:4700::5"]; ok {
		t.Error("a LAN device was flagged as public")
	}
	ip := got["203.0.113.66"]
	if ip.Direction != "both" || ip.Hits != 1 || !slices.Contains(ip.Via, "evil.example.org") ||
		len(ip.Clients) != 1 || ip.Clients[0].IP != "192.168.1.20" || ip.Intel == nil || ip.ASN != 64500 {
		t.Errorf("203.0.113.66: %+v intel %+v", ip, ip.Intel)
	}
	dom := got["evil.example.org"]
	if dom.Direction != "out" || len(dom.Clients) != 1 || dom.Intel == nil || !slices.Contains(dom.Feeds, "feed:tif") {
		t.Errorf("evil.example.org: %+v", dom)
	}

	in, err := x.ro.InboundIPs(store.ListQuery{Since: since}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) == 0 || in[0].IP != "203.0.113.66" || in[0].Verdict != enrich.Malicious {
		t.Errorf("flagged IP isn't first: %+v", in)
	}
	for _, r := range in {
		if r.IP == "2606:4700:4700::5" || strings.HasPrefix(r.IP, "192.168.") {
			t.Errorf("LAN address %s listed as inbound", r.IP)
		}
	}
	doms, err := x.ro.Domains(store.ListQuery{Since: since, Flagged: true})
	if err != nil || len(doms) != 1 || doms[0].Domain != "evil.example.org" || doms[0].Answers == nil {
		t.Errorf("flagged domains: %+v %v", doms, err)
	}
	cl, err := x.ro.Clients(since)
	if err != nil {
		t.Fatal(err)
	}
	if len(cl) == 0 || cl[0].IP != "192.168.1.20" || cl[0].Flagged != 1 || cl[0].FlaggedSamples[0] != "evil.example.org" {
		t.Errorf("clients: %+v", cl)
	}
	p, err := x.ro.IPProfile("203.0.113.66", since, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Intel == nil || p.Intel.Owner != "EXAMPLE-AS" || len(p.Hits) != 1 || len(p.ResolvedBy) != 1 || p.LAN {
		t.Errorf("profile: %+v", p)
	}
	if lan, _ := x.ro.IsLAN("2606:4700:4700::5"); !lan {
		t.Error("v6 LAN device not recognised")
	}
	dp, err := x.ro.DomainProfile("evil.example.org", since)
	if err != nil || len(dp.Answers) != 1 || dp.Answers[0].Intel == nil || dp.Intel == nil {
		t.Errorf("domain profile: %+v %v", dp, err)
	}

	// The owner of the block changes: recorded, and the profile shows it.
	ls.ASN = asnTable(t, "203.0.113.0\t203.0.113.255\t64511\tDE\tNEW-OWNER\n")
	if n, err := x.enr.ReconcileASN(ls.ASN, since, now.Add(time.Hour)); err != nil || n != 4 { // .5, .6, .7 and .66 share the block
		t.Fatalf("asn reconcile changed %d: %v", n, err)
	}
	p, _ = x.ro.IPProfile("203.0.113.66", since, now)
	if len(p.ASNChanges) != 1 || p.ASNChanges[0].NewOwner != "NEW-OWNER" || p.Intel.ASN != 64511 {
		t.Errorf("asn change: %+v %+v", p.ASNChanges, p.Intel)
	}

	// An indicator outside every reconcile window is brought up to date
	// when it's looked at.
	ls.Lists[0] = list(t, "bad", "plain", enrich.Malicious, "198.51.100.200\n")
	if err := x.enr.Rematch("203.0.113.66", ls, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if listed, _, removed, _, _, _ := enrichmentRow(t, x.enr, "feed:bad", "203.0.113.66"); listed || removed == "" {
		t.Errorf("rematch didn't remove: listed %v removed %q", listed, removed)
	}
}

// ipv4only.arpa answers 192.0.0.170/171 (NAT64 discovery). FireHOL lists
// every reserved range, so the address matches a list, but it's not a host:
// it gets the "reserved" verdict and its context, and is never flagged.
func TestReservedAddressesAreContextNotFindings(t *testing.T) {
	x := openExplorer(t)
	x.primary.InsertRecords([]ingest.Record{
		{Query: &ingest.DNSQuery{Hash: "q", TS: now, ClientIP: "192.168.1.20", Domain: "ipv4only.arpa", QType: "AAAA", Source: "t"}},
		{Reply: &ingest.DNSReply{Hash: "r1", TS: now, Domain: "ipv4only.arpa", Answer: "192.0.0.170", Status: "reply", Source: "t"}},
		{Reply: &ingest.DNSReply{Hash: "r2", TS: now, Domain: "ipv4only.arpa", Answer: "192.0.0.171", Status: "reply", Source: "t"}},
	})
	x.index(t)
	bogons := list(t, "firehol1", "plain", enrich.Suspicious, "192.0.0.0/24\n240.0.0.0/4\n")
	if _, err := x.enr.MatchNew(store.Lists{Lists: []*enrich.List{bogons}}, now); err != nil {
		t.Fatal(err)
	}
	since := now.AddDate(0, 0, -1)

	fl, err := x.ro.Flagged(store.FlaggedQuery{Since: since})
	if err != nil {
		t.Fatal(err)
	}
	if len(fl) != 0 {
		t.Errorf("reserved addresses flagged: %+v", fl)
	}
	// Asked for, they come back with who looked them up.
	fl, err = x.ro.Flagged(store.FlaggedQuery{Since: since, Verdicts: []string{enrich.VerdictReserved}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.FlaggedRow{}
	for _, r := range fl {
		got[r.Indicator] = r
	}
	if len(fl) != 3 {
		t.Errorf("reserved: %d rows, want .170, .171 and ipv4only.arpa: %+v", len(fl), fl)
	}
	for _, ind := range []string{"192.0.0.170", "192.0.0.171", "ipv4only.arpa"} {
		r := got[ind]
		if r.Intel == nil || r.Verdict != enrich.VerdictReserved || r.Special == nil || r.Direction != "out" ||
			len(r.Clients) != 1 || r.Clients[0].IP != "192.168.1.20" {
			t.Errorf("reserved %s: %+v intel %+v", ind, r, r.Intel)
		}
	}
	if r := got["192.0.0.170"]; !slices.Contains(r.Via, "ipv4only.arpa") {
		t.Errorf(".170 via = %v", r.Via)
	}
	// Mixed with real verdicts, reserved ones sort last.
	if _, err := x.ro.Flagged(store.FlaggedQuery{Since: since, Verdicts: []string{"malicious", "reserved"}}); err != nil {
		t.Error(err)
	}
	if _, err := x.ro.Flagged(store.FlaggedQuery{Since: since, Verdicts: []string{"bogus"}}); err == nil {
		t.Error("bad verdict accepted")
	}
	in, err := x.ro.Intel([]string{"192.0.0.170", "ipv4only.arpa"}, true)
	if err != nil {
		t.Fatal(err)
	}
	a := in["192.0.0.170"]
	if a == nil || a.Verdict != enrich.VerdictReserved || a.Special == nil || a.Special.RFC != "RFC 7050" ||
		!slices.Contains(a.Feeds, "feed:firehol1") || a.Flagged() {
		t.Errorf("192.0.0.170 intel: %+v", a)
	}
	if d := in["ipv4only.arpa"]; d == nil || d.Verdict != enrich.VerdictReserved || d.Special == nil {
		t.Errorf("ipv4only.arpa intel: %+v", d)
	}

	doms, err := x.ro.Domains(store.ListQuery{Since: since, Flagged: true})
	if err != nil || len(doms) != 0 {
		t.Errorf("flagged domains: %+v %v", doms, err)
	}
	doms, _ = x.ro.Domains(store.ListQuery{Since: since})
	if len(doms) != 1 || doms[0].Domain != "ipv4only.arpa" || doms[0].Verdict != enrich.VerdictReserved || doms[0].Answers != nil || !doms[0].New {
		t.Errorf("domains: %+v", doms)
	}
	cl, _ := x.ro.Clients(since)
	if len(cl) != 1 || cl[0].Flagged != 0 {
		t.Errorf("clients: %+v", cl)
	}
	// The address's page still says who looked it up.
	p, err := x.ro.IPProfile("192.0.0.170", since, now)
	if err != nil || len(p.ResolvedBy) != 1 || p.ResolvedBy[0].Domain != "ipv4only.arpa" ||
		len(p.ResolvedBy[0].Clients) != 1 || p.ResolvedBy[0].Clients[0].IP != "192.168.1.20" {
		t.Errorf("profile: %+v %v", p.ResolvedBy, err)
	}
}

// Bumping the index version re-reads everything, without changing what was
// already indexed.
func TestIndexVersionRereads(t *testing.T) {
	x := openExplorer(t)
	importFile(t, x.primary, "unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}})
	x.index(t)
	snapshot := func() string {
		rows, _ := x.enr.DB().Query(`SELECT indicator, kind, first_seen, last_seen, roles FROM indicators ORDER BY indicator`)
		defer rows.Close()
		var b strings.Builder
		for rows.Next() {
			var a, k, f, l string
			var r int
			rows.Scan(&a, &k, &f, &l, &r)
			b.WriteString(a + k + f + l + strconv.Itoa(r) + "\n")
		}
		return b.String()
	}
	before := snapshot()
	if n, _ := store.IndexNew(x.ro, x.enr, 100); n != 0 {
		t.Fatalf("re-read %d rows without a version change", n)
	}
	x.enr.DB().Exec(`UPDATE meta SET value = '2' WHERE key = 'index_version'`)
	if n, err := store.IndexNew(x.ro, x.enr, 100); err != nil || n == 0 {
		t.Fatalf("old version: re-read %d rows, %v", n, err)
	}
	if after := snapshot(); after != before {
		t.Errorf("re-reading changed the index:\n%s\nvs\n%s", before, after)
	}
}

// Rows that embed Intel keep their own fields and the providers' answers:
// a Domains row's "lookups" (a count) must not hide the answers.
func TestIntelJSONDoesNotCollide(t *testing.T) {
	in := &store.Intel{Verdict: "malicious", Lookups: map[string]*store.LookupFacts{"censys": {Found: true}}}
	b, err := json.Marshal(store.DomainRow{Domain: "x.example", Lookups: 7, Intel: in})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"lookups":7`, `"queried":{"censys":`, `"verdict":"malicious"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s missing from %s", want, b)
		}
	}
	b, _ = json.Marshal(store.InboundIP{IP: "93.184.216.118", Intel: in})
	if !strings.Contains(string(b), `"queried":{"censys":`) {
		t.Errorf("inbound row: %s", b)
	}
}

// A flagged, busy domain ranks first by default, but "recent" puts the
// latest lookup first so quiet names aren't cut off by the limit.
func TestDomainsOrderRecent(t *testing.T) {
	x := openExplorer(t)
	q := func(hash, domain string, ts time.Time) ingest.Record {
		return ingest.Record{Query: &ingest.DNSQuery{Hash: hash, TS: ts, ClientIP: "192.168.1.20", Domain: domain, Source: "test"}}
	}
	x.primary.InsertRecords([]ingest.Record{
		q("a1", "evil.example.org", now.Add(-3*time.Hour)),
		q("a2", "evil.example.org", now.Add(-2*time.Hour)),
		q("b1", "quiet.example.com", now.Add(-time.Minute)),
	})
	x.index(t)
	tif, _ := enrich.ParseList(enrich.Feed{Name: "tif", Format: "plain", Kind: "domain", Verdict: enrich.Malicious}, []byte("example.org\n"))
	if _, err := x.enr.MatchNew(store.Lists{Lists: []*enrich.List{tif}}, now); err != nil {
		t.Fatal(err)
	}
	since := now.AddDate(0, 0, -30)

	doms, err := x.ro.Domains(store.ListQuery{Since: since, Limit: 1})
	if err != nil || len(doms) != 1 || doms[0].Domain != "evil.example.org" {
		t.Errorf("default order: %+v %v", doms, err)
	}
	doms, err = x.ro.Domains(store.ListQuery{Since: since, Order: store.OrderRecent, Limit: 1})
	if err != nil || len(doms) != 1 || doms[0].Domain != "quiet.example.com" {
		t.Errorf("recent order: %+v %v", doms, err)
	}
}

// A refused login makes its address an inbound IP, with the name tried on
// its profile, and indexes it with its own role.
func TestAuthFailuresInbound(t *testing.T) {
	x := openExplorer(t)
	x.primary.InsertRecords([]ingest.Record{
		{Auth: &ingest.AuthFailure{Hash: "a1", TS: now.Add(-time.Hour), Source: "jellyfin", IP: "203.0.113.44", User: "admin"}},
		{Auth: &ingest.AuthFailure{Hash: "a2", TS: now, Source: "jellyfin", IP: "203.0.113.44", User: "root"}},
		{Auth: &ingest.AuthFailure{Hash: "a2", TS: now, Source: "jellyfin", IP: "203.0.113.44", User: "root"}}, // same line again
	})
	x.index(t)
	since := now.AddDate(0, 0, -30)
	in, err := x.ro.InboundIPs(store.ListQuery{Since: since}, now)
	if err != nil || len(in) != 1 || in[0].IP != "203.0.113.44" || in[0].Defenses.Logins != 2 {
		t.Fatalf("inbound: %+v %v", in, err)
	}
	p, err := x.ro.IPProfile("203.0.113.44", since, now)
	if err != nil || len(p.AuthFailures) != 2 || p.AuthFailures[0].User != "root" {
		t.Errorf("profile: %+v %v", p.AuthFailures, err)
	}
	var roles int
	if err := x.enr.DB().QueryRow(`SELECT roles FROM indicators WHERE indicator = '203.0.113.44'`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles&store.RoleAuthFail == 0 {
		t.Errorf("roles = %b, want RoleAuthFail", roles)
	}
}

// The domain page's lookups come from the index plus the not-yet-indexed
// tail, and must match the full scan exactly.
func TestDomainProfileLookupsMatchScan(t *testing.T) {
	x := openExplorer(t)
	q := func(hash, client, domain string, ts time.Time) ingest.Record {
		return ingest.Record{Query: &ingest.DNSQuery{Hash: hash, TS: ts, ClientIP: client, Domain: domain, Source: "test"}}
	}
	x.primary.InsertRecords([]ingest.Record{
		q("1", "192.168.1.20", "example.com", now.Add(-time.Hour)),
		q("2", "192.168.1.20", "a.example.com", now.Add(-time.Hour)),
		q("3", "192.168.1.21", "b.a.example.com", now.Add(-2*time.Hour)),
		q("4", "192.168.1.22", "notexample.com", now.Add(-time.Hour)),   // not a subdomain
		q("5", "192.168.1.23", "x.example.com", now.AddDate(0, 0, -40)), // before the window
		q("6", "192.168.1.20", "printer.lan", now.Add(-time.Hour)),
		q("7", "192.168.1.21", "ipp.printer.lan", now.Add(-time.Hour)),
	})
	x.index(t)
	// Looked up after the last index pass: only the tail finds it.
	x.primary.InsertRecords([]ingest.Record{q("8", "192.168.1.24", "new.example.com", now)})
	since := now.AddDate(0, 0, -30)
	for _, d := range []string{"example.com", "a.example.com", "printer.lan"} {
		want, err := x.ro.DNSByDomain(d, since)
		if err != nil {
			t.Fatal(err)
		}
		p, err := x.ro.DomainProfile(d, since)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(p.Lookups) != fmt.Sprint(want) {
			t.Errorf("%s:\n got %+v\nwant %+v", d, p.Lookups, want)
		}
	}
	if p, _ := x.ro.DomainProfile("example.com", since); len(p.Lookups) != 3 {
		t.Errorf("example.com: %d clients, want 3 (20, 21, 24)", len(p.Lookups))
	}
}

// An inbound connection indexes its source as incoming and nothing for its
// destination, which is our own address.
func TestConnectionIndexesSourceOnly(t *testing.T) {
	x := openExplorer(t)
	x.primary.InsertRecords([]ingest.Record{{Conn: &ingest.Conn{Hash: "c", TS: now, ClientIP: "203.0.113.9",
		DstIP: "198.51.100.200", DstPort: 443, Proto: "tcp", Action: "drop", Rule: "WAN_LOCAL-D-2147483647", Source: "test"}}})
	x.index(t)
	var roles int
	if err := x.enr.DB().QueryRow(`SELECT roles FROM indicators WHERE indicator = '203.0.113.9'`).Scan(&roles); err != nil || roles != store.RoleConnSrc {
		t.Errorf("source roles = %b, %v; want RoleConnSrc", roles, err)
	}
	var n int
	x.enr.DB().QueryRow(`SELECT count(*) FROM indicators WHERE indicator = '198.51.100.200'`).Scan(&n)
	if n != 0 {
		t.Errorf("destination was indexed")
	}
}

// An index from before v3 loses RoleConn in place: an indicator with only
// that role goes (with its feed matches), one with others keeps them, and
// only connections are re-read (other cursors stay put).
func TestIndexV3ClearsRoleConn(t *testing.T) {
	x := openExplorer(t)
	db := x.enr.DB()
	for _, q := range []string{
		`INSERT INTO indicators (indicator, kind, first_seen, last_seen, roles) VALUES ('198.51.100.200', 'ip', 'a', 'b', 64)`,
		`INSERT INTO indicators (indicator, kind, first_seen, last_seen, roles) VALUES ('198.51.100.201', 'ip', 'a', 'b', 96)`,
		`INSERT INTO indicators (indicator, kind, first_seen, last_seen, roles) VALUES ('203.0.113.9', 'ip', 'a', 'b', 256)`,
		`INSERT INTO cursors (tbl, last_id) VALUES ('hits', 42) ON CONFLICT(tbl) DO UPDATE SET last_id = 42`,
		`INSERT INTO cursors (tbl, last_id) VALUES ('connections', 42) ON CONFLICT(tbl) DO UPDATE SET last_id = 42`,
		`INSERT INTO meta (key, value) VALUES ('index_version', '2') ON CONFLICT(key) DO UPDATE SET value = '2'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// One outbound connection (LAN source) and one inbound (public source),
	// read again from the start.
	x.primary.InsertRecords([]ingest.Record{
		{Conn: &ingest.Conn{Hash: "out", TS: now, ClientIP: "192.168.1.20", DstIP: "198.51.100.210", DstPort: 443, Proto: "tcp", Action: "accept", Source: "test"}},
		{Conn: &ingest.Conn{Hash: "in", TS: now, ClientIP: "203.0.113.10", DstIP: "198.51.100.200", DstPort: 443, Proto: "tcp", Action: "drop", Source: "test"}},
	})
	x.index(t) // IndexNew runs the version step first
	got := map[string]int{}
	rows, err := db.Query(`SELECT indicator, roles FROM indicators`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var i string
		var r int
		rows.Scan(&i, &r)
		got[i] = r
	}
	rows.Close()
	want := map[string]int{
		"198.51.100.201": store.RoleAnswer,  // kept its other role
		"203.0.113.9":    store.RoleConnSrc, // untouched
		"198.51.100.210": store.RoleConn,    // a LAN device went there
		"203.0.113.10":   store.RoleConnSrc, // came at us
		// 198.51.100.200 (RoleConn only, and an inbound row's destination) is gone
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("indicators = %v\nwant %v", got, want)
	}
	var last int
	db.QueryRow(`SELECT last_id FROM cursors WHERE tbl = 'hits'`).Scan(&last)
	if last != 42 {
		t.Errorf("hits cursor = %d, want 42 (no re-read)", last)
	}
}

// A LAN device known only from the neighbour table (it never used the
// router's DNS) is still LAN: not inbound, and IsLAN says so.
func TestNeighbourOnlyDeviceIsLAN(t *testing.T) {
	x := openExplorer(t)
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	const v6 = "2001:db8:5::7"
	x.primary.InsertRecords([]ingest.Record{{Seen: &ingest.Sighting{Hash: "n1", TS: now.Add(-time.Hour), IP: v6,
		MAC: "02:00:00:00:00:07", Source: "router-neigh"}}})
	x.primary.InsertHits([]hit.Hit{{Hash: "h1", TS: now.Add(-time.Hour), Site: "jf", Source: "caddy", ClientIP: v6, Path: "/", Status: 200},
		{Hash: "h2", TS: now.Add(-time.Hour), Site: "jf", Source: "caddy", ClientIP: "203.0.113.5", Path: "/", Status: 200}})
	in, err := x.ro.InboundIPs(store.ListQuery{Since: now.Add(-24 * time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 1 || in[0].IP != "203.0.113.5" {
		t.Errorf("inbound = %+v, want only 203.0.113.5", in)
	}
	if lan, err := x.ro.IsLAN(v6); err != nil || !lan {
		t.Errorf("IsLAN(%s) = %v, %v", v6, lan, err)
	}
}

// Every inbound address gets its first and last event from whatever it did,
// not only from web hits, and what we did about it is one Defenses tally.
func TestInboundTimesAndDefenses(t *testing.T) {
	x := openExplorer(t)
	st := x.primary
	t0 := time.Now().UTC().Truncate(time.Second) // Bans30d counts back from the wall clock
	at := func(d time.Duration) time.Time { return t0.Add(-d) }
	const (
		idsOnly   = "198.51.100.10"
		banOnly   = "198.51.100.11"
		tripOnly  = "198.51.100.12"
		loginOnly = "198.51.100.13"
		mixed     = "198.51.100.14"
		dropOnly  = "198.51.100.15"
	)
	alert := func(h, ip, action string, ts time.Time) ingest.Record {
		return ingest.Record{Alert: &ingest.IDSAlert{Hash: h, TS: ts, SrcIP: ip, DstIP: "192.0.2.1", Action: action, Source: "unifi-cef"}}
	}
	conn := func(h, ip, action string, ts time.Time) ingest.Record {
		return ingest.Record{Conn: &ingest.Conn{Hash: h, TS: ts, ClientIP: ip, DstIP: "192.0.2.1", DstPort: 22, Proto: "tcp",
			Action: action, Rule: "WAN_LOCAL-D-1", Source: "unifi-fw"}}
	}
	if _, err := st.InsertRecords([]ingest.Record{
		alert("i1", idsOnly, "blocked", at(5*time.Hour)),
		alert("i2", idsOnly, "blocked", at(2*time.Hour)),
		alert("i3", idsOnly, "blocked", at(20*24*time.Hour)), // outside the window, inside 30 days
		alert("i4", idsOnly, "blocked", at(40*24*time.Hour)), // older than 30 days
		alert("m1", mixed, "allowed", at(time.Hour)),
		conn("c1", idsOnly, "drop", at(8*time.Hour)),       // counted for a listed address, and its first event
		conn("c2", idsOnly, "drop", at(25*24*time.Hour)),   // 30 days only
		conn("c3", mixed, "accept", at(7*time.Hour)),       // let through: not a defense, not an event here
		conn("c4", dropOnly, "drop", at(10*time.Minute)),   // only listed when asked for
		conn("c5", dropOnly, "reject", at(20*time.Minute)), // rejects count as drops
		{Auth: &ingest.AuthFailure{Hash: "l1", TS: at(3 * time.Hour), Source: "jellyfin", IP: loginOnly, User: "admin"}},
	}); err != nil {
		t.Fatal(err)
	}
	ban(t, st, ingest.Ban{TS: at(4 * time.Hour), Event: "ban", Jail: "sshd", IP: banOnly})
	if _, err := st.InsertTrip(store.Trip{TrippedAt: at(30 * time.Minute), CooldownUntil: t0, Breaker: "probe", Key: tripOnly,
		Reason: "test", FirstSeen: at(time.Hour), Detail: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	addHits(t, st, mixed, "jellyfin.example", at(6*time.Hour))

	in, err := x.ro.InboundIPs(store.ListQuery{Since: at(24 * time.Hour), Order: store.OrderRecent}, t0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.InboundIP{}
	for _, r := range in {
		got[r.IP] = r
	}
	for _, c := range []struct {
		ip          string
		first, last time.Time
		d           store.Defenses
		d30         int64
	}{
		{idsOnly, at(8 * time.Hour), at(2 * time.Hour), store.Defenses{Total: 3, IDS: 2, Firewall: 1}, 5},
		{banOnly, at(4 * time.Hour), at(4 * time.Hour), store.Defenses{Total: 1, Bans: 1}, 1},
		{tripOnly, at(30 * time.Minute), at(30 * time.Minute), store.Defenses{Total: 1, Trips: 1}, 1},
		{loginOnly, at(3 * time.Hour), at(3 * time.Hour), store.Defenses{Total: 1, Logins: 1}, 1},
		{mixed, at(6 * time.Hour), at(time.Hour), store.Defenses{AlertsAllowed: 1}, 0}, // first from the hit, last from the alert
	} {
		r, ok := got[c.ip]
		if !ok {
			t.Errorf("%s missing", c.ip)
			continue
		}
		if !r.First.Equal(c.first) || !r.Last.Equal(c.last) {
			t.Errorf("%s: first %v last %v, want %v %v", c.ip, r.First, r.Last, c.first, c.last)
		}
		if r.Defenses != c.d || r.Defenses30d != c.d30 {
			t.Errorf("%s: defenses %+v (30d %d), want %+v (30d %d)", c.ip, r.Defenses, r.Defenses30d, c.d, c.d30)
		}
	}
	if len(in) != 5 || in[0].IP != tripOnly || in[1].IP != mixed {
		t.Errorf("recent order: %v", ips(in))
	}

	// Asked for, addresses the firewall only dropped are listed too.
	in, err = x.ro.InboundIPs(store.ListQuery{Since: at(24 * time.Hour), Order: store.OrderRecent, Drops: true}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 6 || in[0].IP != dropOnly {
		t.Fatalf("with drops: %v", ips(in))
	}
	if r := in[0]; r.Defenses != (store.Defenses{Total: 2, Firewall: 2}) || r.Defenses30d != 2 ||
		!r.First.Equal(at(20*time.Minute)) || !r.Last.Equal(at(10*time.Minute)) {
		t.Errorf("drop-only: %+v", r)
	}
	for _, r := range in {
		if r.IP == idsOnly && r.Defenses.Firewall != 1 {
			t.Errorf("idsOnly with drops: %+v", r.Defenses)
		}
	}
}

func ips(in []store.InboundIP) []string {
	var out []string
	for _, r := range in {
		out = append(out, r.IP)
	}
	return out
}
