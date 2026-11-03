package store_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"dnscount/enrich"
	"dnscount/hit"
	"dnscount/ingest"
	"dnscount/ingest/dns"
	"dnscount/ingest/fw"
	"dnscount/ingest/ids"
	"dnscount/store"
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
	if _, err := x.ro.DB().Exec(`INSERT INTO counters (site, count) VALUES ('x', 1)`); err == nil {
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
	err := st.DB().QueryRow(`SELECT listed, first_listed, removed_at, detail, list_version FROM enrichment
		WHERE provider = ? AND indicator = ?`, provider, ind).Scan(&listed, &first, &removed, &detail, &version)
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
	if in[0].ByName != 1 || in[0].ByIP != 0 {
		t.Errorf("by name / by IP = %d / %d", in[0].ByName, in[0].ByIP)
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
