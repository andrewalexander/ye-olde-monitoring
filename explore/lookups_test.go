package explore

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"dnscount/enrich"
	"dnscount/hit"
	"dnscount/ingest"
	"dnscount/store"
)

// fakeProvider records everything sent to it.
type fakeProvider struct {
	name  string
	kinds []string
	batch int
	sent  []string
	calls int
	fail  error // returned from the next call
}

func (f *fakeProvider) Name() string             { return f.name }
func (f *fakeProvider) Handles(kind string) bool { return slices.Contains(f.kinds, kind) }
func (f *fakeProvider) BatchSize() int           { return f.batch }
func (f *fakeProvider) Lookup(_ context.Context, inds []string) ([]enrich.Answer, int, error) {
	f.calls++
	f.sent = append(f.sent, inds...)
	if f.fail != nil {
		return nil, 1, f.fail
	}
	var out []enrich.Answer
	for _, i := range inds {
		out = append(out, enrich.Answer{Indicator: i, Found: i != "198.18.0.1", Facts: map[string]any{"seen_by": f.name}})
	}
	return out, len(inds), nil
}

type lookupWorld struct {
	primary, enr, ro *store.Store
	now              time.Time
}

func newLookupWorld(t *testing.T) *lookupWorld {
	t.Helper()
	dir := t.TempDir()
	p, err := store.Open(filepath.Join(dir, "dnscount.db"))
	if err != nil {
		t.Fatal(err)
	}
	enr, err := store.OpenEnrich(filepath.Join(dir, "explore.db"))
	if err != nil {
		t.Fatal(err)
	}
	ro, err := store.OpenReadOnly(filepath.Join(dir, "dnscount.db"), filepath.Join(dir, "explore.db"), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close(); enr.Close(); p.Close() })
	w := &lookupWorld{primary: p, enr: enr, ro: ro, now: time.Now().UTC().Truncate(time.Second)}

	hits := func(ip string, n int) {
		for i := 0; i < n; i++ {
			p.InsertHits([]hit.Hit{{Hash: ip + string(rune('a'+i)), TS: w.now.Add(-time.Hour), Site: "jf", Source: "caddy",
				ClientIP: ip, Host: "jf.example", Path: "/.env", Status: 404}})
		}
	}
	hits("185.242.226.118", 5) // banned below: a candidate
	hits("8.8.4.4", 2)         // flagged by a list below: a candidate
	hits("9.9.9.9", 3)         // nothing against it: not a candidate
	p.InsertBan(ingest.Ban{TS: w.now.Add(-30 * time.Minute), Event: "ban", Jail: "caddy-probe", IP: "185.242.226.118"})
	// A public-looking address that's really a LAN device (seen in the
	// neighbour table), with a ban against it: never sent anywhere.
	hits("2606:4700:10::5", 1)
	p.InsertBan(ingest.Ban{TS: w.now.Add(-20 * time.Minute), Event: "ban", Jail: "jellyfin", IP: "2606:4700:10::5"})
	p.InsertRecords([]ingest.Record{
		{Seen: &ingest.Sighting{Hash: "n1", TS: w.now, IP: "2606:4700:10::5", MAC: "02:00:00:00:00:05", Source: "router-neigh"}},
		// A LAN device looks up a flagged domain, which resolved to an address.
		{Query: &ingest.DNSQuery{Hash: "q1", TS: w.now.Add(-time.Hour), ClientIP: "192.168.1.20", Domain: "evil.example.org", Source: "t"}},
		{Reply: &ingest.DNSReply{Hash: "r1", TS: w.now.Add(-time.Hour), Domain: "evil.example.org", Answer: "93.184.216.99", Status: "reply", Source: "t"}},
		// And our own site, also on the list (as a test of the gate).
		{Query: &ingest.DNSQuery{Hash: "q2", TS: w.now.Add(-time.Hour), ClientIP: "192.168.1.20", Domain: "jellyfin.ourname.test", Source: "t"}},
	})
	if _, err := store.IndexNew(ro, enr, 0); err != nil {
		t.Fatal(err)
	}
	bad, _ := enrich.ParseList(enrich.Feed{Name: "bad", Format: "plain", Kind: "domain", Verdict: enrich.Malicious},
		[]byte("8.8.4.4\nexample.org\nourname.test\n2606:4700:10::5\n"))
	if _, err := enr.MatchNew(store.Lists{Lists: []*enrich.List{bad}}, w.now); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *lookupWorld) run(t *testing.T, ps []ProviderRun, mod func(*LookupRun)) ([]ProviderResult, string) {
	t.Helper()
	var out strings.Builder
	r := &LookupRun{RO: w.ro, Enr: w.enr, Providers: ps, Never: []string{"ourname.test"}, Now: func() time.Time { return w.now }, Out: &out}
	if mod != nil {
		mod(r)
	}
	res, err := r.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res, out.String()
}

func TestLookupRun(t *testing.T) {
	w := newLookupWorld(t)
	ipOnly := &fakeProvider{name: "abuseipdb", kinds: []string{"ip"}, batch: 1}
	both := &fakeProvider{name: "censys", kinds: []string{"ip", "domain"}, batch: 100}
	limits := ProviderLimits{Daily: 100, TTL: "168h"}

	// A dry run sends nothing, and says what it would do and why.
	_, out := w.run(t, []ProviderRun{{ipOnly, limits}, {both, limits}}, func(r *LookupRun) { r.DryRun = true })
	if ipOnly.calls+both.calls != 0 {
		t.Fatalf("dry run made %d calls", ipOnly.calls+both.calls)
	}
	for _, want := range []string{"185.242.226.118", "banned 1× in 30d", "8.8.4.4", "malicious (bad)",
		"evil.example.org", "93.184.216.99", "resolved to it", "never sent (privacy gate)", "one of our own names"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	// A LAN device with a public-looking address isn't even a candidate.
	if strings.Contains(out, "2606:4700:10::5") {
		t.Errorf("a LAN device is a candidate:\n%s", out)
	}

	// The real run, worst first: by verdict, then inbound before outgoing at
	// the same verdict (so a malicious outgoing address beats an inbound
	// one that's only banned); only what each provider handles.
	w.run(t, []ProviderRun{{ipOnly, limits}, {both, limits}}, nil)
	if want := []string{"8.8.4.4", "93.184.216.99", "185.242.226.118"}; !slices.Equal(ipOnly.sent, want) {
		t.Errorf("abuseipdb asked about %v, want %v", ipOnly.sent, want)
	}
	if !slices.Contains(both.sent, "evil.example.org") || both.calls != 1 {
		t.Errorf("censys: %v in %d calls (want one batch with the domain)", both.sent, both.calls)
	}
	for _, p := range [][]string{ipOnly.sent, both.sent} {
		for _, s := range p {
			if s == "2606:4700:10::5" || strings.HasSuffix(s, "ourname.test") || s == "9.9.9.9" || s == "192.168.1.20" {
				t.Errorf("sent %s", s)
			}
		}
	}

	// The answers are in the enrichment store, and the explorer shows them.
	in, err := w.ro.Intel([]string{"185.242.226.118"}, false)
	if err != nil || in["185.242.226.118"] == nil || in["185.242.226.118"].Lookups["abuseipdb"] == nil ||
		!in["185.242.226.118"].Lookups["abuseipdb"].Found {
		t.Fatalf("intel: %+v %v", in["185.242.226.118"], err)
	}
	// Queried answers are context: they don't make anything flagged.
	if in["185.242.226.118"].Verdict != "" {
		t.Errorf("a lookup set a verdict: %+v", in["185.242.226.118"])
	}

	// Within the TTL nothing is asked again.
	before := ipOnly.calls
	w.run(t, []ProviderRun{{ipOnly, limits}}, nil)
	if ipOnly.calls != before {
		t.Errorf("re-asked within the TTL")
	}
	// After it, it is.
	w.now = w.now.Add(8 * 24 * time.Hour)
	w.run(t, []ProviderRun{{ipOnly, limits}}, func(r *LookupRun) { r.Since = 30 * 24 * time.Hour })
	if ipOnly.calls == before {
		t.Errorf("didn't re-ask after the TTL")
	}
}

func TestLookupBudget(t *testing.T) {
	w := newLookupWorld(t)
	p := &fakeProvider{name: "abuseipdb", kinds: []string{"ip"}, batch: 1}
	// Two units a day: the first run spends both, the second nothing.
	lim := ProviderLimits{Daily: 2, TTL: "168h"}
	res, out := w.run(t, []ProviderRun{{p, lim}}, nil)
	if p.calls != 2 || res[0].Units != 2 || !strings.Contains(out, "1 over budget") {
		t.Errorf("first run: %d calls %+v\n%s", p.calls, res, out)
	}
	w.run(t, []ProviderRun{{p, lim}}, nil)
	if p.calls != 2 {
		t.Errorf("budget not counted across runs: %d calls", p.calls)
	}
	// A monthly cap too, and -limit.
	w.now = w.now.Add(25 * time.Hour)
	q := &fakeProvider{name: "censys", kinds: []string{"ip"}, batch: 1}
	w.run(t, []ProviderRun{{q, ProviderLimits{Monthly: 100, TTL: "720h"}}}, func(r *LookupRun) { r.Limit = 1 })
	if q.calls != 1 {
		t.Errorf("-limit 1: %d calls", q.calls)
	}

	// Asked for by hand, still gated: a LAN address never goes, a public one does.
	h := &fakeProvider{name: "internetdb", kinds: []string{"ip"}, batch: 1}
	w.run(t, []ProviderRun{{h, ProviderLimits{Daily: 10, TTL: "1h"}}}, func(r *LookupRun) {
		r.Extra = []string{"192.168.1.20", "2606:4700:10::5", "1.1.1.1"}
	})
	if !slices.Contains(h.sent, "1.1.1.1") || slices.Contains(h.sent, "192.168.1.20") || slices.Contains(h.sent, "2606:4700:10::5") {
		t.Errorf("by hand: %v", h.sent)
	}
	if h.sent[0] != "1.1.1.1" {
		t.Errorf("asked-for indicators should go first: %v", h.sent)
	}
}

func TestLookupStops(t *testing.T) {
	w := newLookupWorld(t)
	p := &fakeProvider{name: "abuseipdb", kinds: []string{"ip"}, batch: 1,
		fail: &enrich.StopError{Provider: "abuseipdb", Status: 401, Message: "Authentication failed"}}
	res, out := w.run(t, []ProviderRun{{p, ProviderLimits{Daily: 10, TTL: "1h"}}}, nil)
	if p.calls != 1 || res[0].Stopped == "" || !strings.Contains(out, "stopped") {
		t.Errorf("didn't stop on a refusal: %d calls %+v", p.calls, res)
	}
	// The refusal is logged and shows as the last error.
	u, err := w.enr.LookupUsage("", w.now)
	if err != nil || len(u) != 1 || !strings.Contains(u[0].LastError, "Authentication failed") || u[0].Day != 1 {
		t.Errorf("usage: %+v %v", u, err)
	}
}

func TestKeysAndConfig(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "secrets.env")
	writeFile(t, kf, "# keys\nABUSE_IPDB_KEY=abc123\nexport CENSYS_TOKEN=\"tok\"\n")
	keys, err := LoadKeys(kf)
	if err != nil || keys[KeyAbuseIPDB] != "abc123" || keys[KeyCensys] != "tok" {
		t.Errorf("keys: %v %v", len(keys), err)
	}
	if k, err := LoadKeys(filepath.Join(dir, "missing.env")); err != nil || len(k) != 0 {
		t.Errorf("a missing key file should be no keys: %v %v", len(k), err)
	}
	if _, err := NewProvider("abuseipdb", ProviderLimits{}, map[string]string{}); err == nil ||
		!strings.Contains(err.Error(), KeyAbuseIPDB) {
		t.Errorf("missing key: %v", err)
	}
	cf := filepath.Join(dir, "lookups.json")
	writeFile(t, cf, `{"never":["ourname.test"],"automatic":["internetdb"],"providers":{"censys":{"monthly":50}}}`)
	c, err := LoadLookupsConfig(cf)
	if err != nil || c.Providers["censys"].Monthly != 50 || c.Providers["censys"].TTL != "720h" ||
		c.Providers["abuseipdb"].Daily != 800 || !slices.Equal(c.Automatic, []string{"internetdb"}) {
		t.Errorf("config: %+v %v", c, err)
	}
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
