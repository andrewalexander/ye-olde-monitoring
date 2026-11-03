package enrich

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func feed(name, format, kind string) Feed {
	return Feed{Name: name, Format: format, Kind: kind, Verdict: Malicious, Interval: time.Hour}
}

func TestParseFormats(t *testing.T) {
	cases := []struct {
		f     Feed
		in    string
		match map[string]string // indicator -> via ("" = no match)
	}{
		{feed("plain", "plain", "ip"), "# comment\n203.0.113.66\n198.51.100.0/24 ; note\n2001:db8::/32\n",
			map[string]string{"203.0.113.66": "203.0.113.66", "198.51.100.7": "198.51.100.0/24",
				"2001:db8::5": "2001:db8::/32", "192.0.2.1": ""}},
		{feed("hosts", "hosts", "domain"), "127.0.0.1 localhost\n0.0.0.0 example.org # ad\n0.0.0.0 ads.example.net\n",
			map[string]string{"evil.example.org": "example.org", "example.org": "example.org",
				"example.net": "", "localhost": "", "ads.example.net.": "ads.example.net"}},
		{feed("url", "url", "domain"), "http://phish.example.com/login?x=1\nhttps://203.0.113.9:8443/a\n",
			map[string]string{"phish.example.com": "phish.example.com", "203.0.113.9": "203.0.113.9", "example.com": ""}},
		{feed("drop", "spamhaus", "ip"), `{"cidr":"203.0.113.0/24","sblid":"SBL1","rir":"x"}` + "\n" +
			`{"type":"metadata","records":1}` + "\n",
			map[string]string{"203.0.113.200": "203.0.113.0/24"}},
		{feed("tld", "plain", "domain"), "com\nexample.co.uk\n",
			map[string]string{"x.com": "", "a.example.co.uk": "example.co.uk", "co.uk": ""}},
	}
	for _, c := range cases {
		l, err := ParseList(c.f, []byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.f.Name, err)
		}
		for ind, want := range c.match {
			via, _, ok := l.Match(ind)
			if ok != (want != "") || via != want {
				t.Errorf("%s: Match(%s) = %q, %v; want %q", c.f.Name, ind, via, ok, want)
			}
		}
	}
	l, _ := ParseList(feed("drop", "spamhaus", "ip"), []byte(`{"cidr":"203.0.113.0/24","sblid":"SBL1"}`))
	if _, d, _ := l.Match("203.0.113.1"); d != "SBL1" {
		t.Errorf("spamhaus detail = %q", d)
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestASN(t *testing.T) {
	tab, err := ParseASN(gz("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"203.0.113.0\t203.0.113.255\t64500\tNL\tEXAMPLE-AS\n" +
		"203.0.114.0\t203.0.114.255\t0\tNone\tNot routed\n" +
		"2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64501\tDE\tV6-AS\n"))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]uint32{"203.0.113.66": 64500, "1.0.0.1": 13335, "203.0.114.5": 0,
		"2001:db8::1": 64501, "9.9.9.9": 0, "::ffff:203.0.113.1": 64500} {
		a, ok := tab.Lookup(ip)
		if ok != (want != 0) || a.Number != want {
			t.Errorf("Lookup(%s) = %+v, %v; want %d", ip, a, ok, want)
		}
	}
	if a, _ := tab.Lookup("203.0.113.1"); a.Owner != "EXAMPLE-AS" || a.Country != "NL" {
		t.Errorf("got %+v", a)
	}
}

func TestPublic(t *testing.T) {
	for ip, want := range map[string]bool{"203.0.113.1": true, "10.1.2.3": false, "100.64.1.1": false,
		"127.0.0.1": false, "fe80::1": false, "fd00::1": false, "2606:4700:4700::1": true, "*": false, "0.0.0.0": false} {
		if _, ok := PublicIP(ip); ok != want {
			t.Errorf("PublicIP(%s) = %v", ip, ok)
		}
	}
	for d, want := range map[string]bool{"example.com": true, "mac": false, "printer.lan": false,
		"1.0.168.192.in-addr.arpa": false, "x.home.arpa": false, "Example.COM.": true, "a b.com": false} {
		if _, ok := PublicDomain(d); ok != want {
			t.Errorf("PublicDomain(%s) = %v", d, ok)
		}
	}
}

func TestFetch(t *testing.T) {
	body := atomic.Value{}
	body.Store("203.0.113.1\n203.0.113.2\n")
	var hits, conditional atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` && body.Load() == "203.0.113.1\n203.0.113.2\n" {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Query().Get("key") != "" && r.URL.Query().Get("key") != "sekrit" {
			http.Error(w, "bad key", 403)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	dir := t.TempDir()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	f := Feed{Name: "t", URL: srv.URL, Kind: "ip", Format: "plain", Verdict: Malicious, Interval: time.Hour}
	x := &Fetcher{Dir: dir, Now: func() time.Time { return now }}
	ctx := context.Background()

	if ch, err := x.Update(ctx, []Feed{f}); err != nil || len(ch) != 1 {
		t.Fatalf("first update: %v %v", ch, err)
	}
	// Not due yet: no request at all.
	now = now.Add(30 * time.Minute)
	x.Update(ctx, []Feed{f})
	if hits.Load() != 1 {
		t.Fatalf("fetched a feed younger than its interval (%d requests)", hits.Load())
	}
	// Due: conditional request, 304, file kept.
	now = now.Add(time.Hour)
	if ch, err := x.Update(ctx, []Feed{f}); err != nil || len(ch) != 0 || conditional.Load() != 1 {
		t.Fatalf("304 update: changed %v, err %v, conditional %d", ch, err, conditional.Load())
	}
	st, _ := ReadState(dir)
	if !st["t"].LastOK.Equal(now) {
		t.Errorf("304 didn't count as a good fetch: %+v", st["t"])
	}
	// A truncated download (garbage, 0 entries) is rejected.
	body.Store("<html>oops</html>\n")
	now = now.Add(2 * time.Hour)
	if _, err := x.Update(ctx, []Feed{f}); err == nil {
		t.Fatal("garbage download accepted")
	}
	b, _ := os.ReadFile(f.File(dir))
	if !strings.Contains(string(b), "203.0.113.2") {
		t.Fatalf("old file replaced: %q", b)
	}
	st, _ = ReadState(dir)
	if st["t"].Entries != 2 || st["t"].LastError == "" {
		t.Errorf("state after rejected download: %+v", st["t"])
	}
	// Stale after 3 intervals without a good fetch.
	if !st["t"].Stale(f, now.Add(4*time.Hour)) {
		t.Error("not stale after 3 intervals")
	}

	// A key in the URL: skipped when unset, filled (and kept out of state) when set.
	kf := Feed{Name: "k", URL: srv.URL + "/?key={TEST_KEY}", Kind: "ip", Format: "plain", Verdict: Malicious, Interval: time.Hour}
	body.Store("203.0.113.9\n")
	x.Getenv = func(string) string { return "" }
	x.Update(ctx, []Feed{kf})
	st, _ = ReadState(dir)
	if st["k"].Skipped == "" || st["k"].Stale(kf, now) {
		t.Errorf("missing key: %+v", st["k"])
	}
	x.Getenv = func(string) string { return "sekrit" }
	if ch, err := x.Update(ctx, []Feed{kf}); err != nil || len(ch) != 1 {
		t.Fatalf("keyed update: %v %v", ch, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), "sekrit") {
		t.Error("key leaked into state.json")
	}
}

func TestLoadFeeds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "extra.json")
	os.WriteFile(p, []byte(`[{"name":"mine","url":"/etc/bad.txt","kind":"ip","format":"plain","verdict":"malicious","interval":"10m"},
		{"name":"tor-exits","url":"/x","format":"plain","verdict":"info"}]`), 0o600)
	fs, err := LoadFeeds(p, []string{"stevenblack"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range fs {
		names = append(names, f.Name)
		if f.Name == "mine" && f.Interval != 10*time.Minute {
			t.Errorf("interval = %v", f.Interval)
		}
		if f.Name == "tor-exits" && f.Verdict != Info {
			t.Error("extra feed didn't replace the built-in one")
		}
	}
	if strings.Contains(strings.Join(names, ","), "stevenblack") || !strings.Contains(strings.Join(names, ","), "mine") {
		t.Errorf("feeds = %v", names)
	}
}
