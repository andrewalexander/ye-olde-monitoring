package enrich

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../testdata/lookups/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// noWait makes the providers' pacing and Retry-After instant, and records
// what they would have waited.
func noWait(c *httpCaller, waited *[]time.Duration) {
	c.Sleep = func(_ context.Context, d time.Duration) error {
		if waited != nil {
			*waited = append(*waited, d)
		}
		return nil
	}
}

func TestInternetDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/8.8.8.8":
			w.Write(fixture(t, "internetdb.json"))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"detail":"No information available"}`))
		}
	}))
	defer srv.Close()
	p := NewInternetDB(srv.URL)
	noWait(&p.http, nil)
	a, units, err := p.Lookup(context.Background(), []string{"8.8.8.8"})
	if err != nil || units != 1 || len(a) != 1 || !a[0].Found {
		t.Fatalf("lookup: %+v %d %v", a, units, err)
	}
	f, _ := json.Marshal(a[0].Facts)
	if !strings.Contains(string(f), `"ports":[53,443]`) || !strings.Contains(string(f), `"hostnames":["dns.google"]`) {
		t.Errorf("facts: %s", f)
	}
	a, _, err = p.Lookup(context.Background(), []string{"1.0.0.9"})
	if err != nil || len(a) != 1 || a[0].Found {
		t.Errorf("404 should be an answer saying not found: %+v %v", a, err)
	}
}

func TestAbuseIPDB(t *testing.T) {
	var remaining atomic.Value
	remaining.Store("999")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "k3y" || r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(401)
			w.Write([]byte(`{"errors":[{"detail":"Authentication failed"}]}`))
			return
		}
		if r.URL.Query().Get("maxAgeInDays") != "90" || r.URL.Query().Get("ipAddress") == "" {
			w.WriteHeader(422)
			return
		}
		w.Header().Set("X-RateLimit-Remaining", remaining.Load().(string))
		w.Write(fixture(t, "abuseipdb.json"))
	}))
	defer srv.Close()

	p := NewAbuseIPDB(srv.URL, "k3y")
	noWait(&p.http, nil)
	a, _, err := p.Lookup(context.Background(), []string{"185.242.226.118"})
	if err != nil || len(a) != 1 || !a[0].Found {
		t.Fatalf("lookup: %+v %v", a, err)
	}
	if a[0].Facts["score"] != 100 || a[0].Facts["reports"] != 412 || a[0].Facts["usage"] != "Data Center/Web Hosting/Transit" {
		t.Errorf("facts: %+v", a[0].Facts)
	}
	// The last check of the day: answered, then the provider stops.
	remaining.Store("0")
	if _, _, err := p.Lookup(context.Background(), []string{"185.242.226.118"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Lookup(context.Background(), []string{"185.242.226.118"}); !IsStop(err) {
		t.Errorf("after X-RateLimit-Remaining: 0, want a stop, got %v", err)
	}

	// A bad key stops the provider, and the key isn't in the error.
	bad := NewAbuseIPDB(srv.URL, "wrong-key")
	noWait(&bad.http, nil)
	_, _, err = bad.Lookup(context.Background(), []string{"185.242.226.118"})
	if !IsStop(err) || strings.Contains(err.Error(), "wrong-key") {
		t.Errorf("bad key: %v", err)
	}
}

func TestRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			return
		}
		w.Write(fixture(t, "internetdb.json"))
	}))
	defer srv.Close()
	p := NewInternetDB(srv.URL)
	var waited []time.Duration
	noWait(&p.http, &waited)
	if _, _, err := p.Lookup(context.Background(), []string{"8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	waited7 := false
	for _, d := range waited {
		waited7 = waited7 || d == 7*time.Second
	}
	if calls.Load() != 2 || !waited7 {
		t.Errorf("calls %d, waited %v; want a retry after 7s", calls.Load(), waited)
	}

	// Always 429: gives up after a few tries, as a stop.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
	}))
	defer srv2.Close()
	p2 := NewInternetDB(srv2.URL)
	noWait(&p2.http, nil)
	if _, _, err := p2.Lookup(context.Background(), []string{"8.8.8.8"}); !IsStop(err) {
		t.Errorf("endless 429: %v", err)
	}
}

func TestCensys(t *testing.T) {
	var bulk, single, web atomic.Int32
	var bulkAllowed atomic.Bool
	bulkAllowed.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t0ken" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/v3/global/asset/host":
			bulk.Add(1)
			if !bulkAllowed.Load() {
				w.WriteHeader(403)
				w.Write([]byte(`{"error":"not available on your plan"}`))
				return
			}
			b, _ := io.ReadAll(r.Body)
			var in struct {
				HostIDs []string `json:"host_ids"`
			}
			json.Unmarshal(b, &in)
			if r.Header.Get("Accept") != censysHostType || len(in.HostIDs) != 2 {
				w.WriteHeader(422)
				return
			}
			w.Write(fixture(t, "censys-hosts.json")) // knows one of the two
		case r.Method == "GET" && r.URL.Path == "/v3/global/asset/host/185.242.226.118":
			single.Add(1)
			var env struct {
				Result []json.RawMessage `json:"result"`
			}
			json.Unmarshal(fixture(t, "censys-hosts.json"), &env)
			w.Write([]byte(`{"result":` + string(env.Result[0]) + `}`))
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v3/global/asset/host/"):
			single.Add(1)
			w.WriteHeader(404)
		case r.Method == "GET" && r.URL.Path == "/v3/global/asset/webproperty/jssdk.juneworewyjyna.com:443":
			web.Add(1)
			if r.Header.Get("Accept") != censysWebType {
				w.WriteHeader(422)
				return
			}
			w.Write(fixture(t, "censys-webproperty.json"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewCensys(srv.URL, "t0ken")
	noWait(&p.http, nil)
	inds := []string{"185.242.226.118", "203.0.0.1", "jssdk.juneworewyjyna.com"}
	a, units, err := p.Lookup(context.Background(), inds)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Answer{}
	for _, x := range a {
		got[x.Indicator] = x
	}
	if bulk.Load() != 1 || single.Load() != 0 || web.Load() != 1 || len(a) != 3 {
		t.Fatalf("requests: bulk %d single %d web %d; answers %d", bulk.Load(), single.Load(), web.Load(), len(a))
	}
	if units != 2 { // one bulk result, one web property; nothing for the unknown host
		t.Errorf("units = %d", units)
	}
	h := got["185.242.226.118"]
	f, _ := json.Marshal(h.Facts)
	for _, want := range []string{`"asn":202425`, `"port":22`, `"openbsd openssh 8.9"`, `"CVE-2023-44487"`, `"labels":["SCANNER"]`,
		`"greynoise":"malicious"`, `"dns_names":["scanner.example.net"]`} {
		if !strings.Contains(string(f), want) {
			t.Errorf("host facts lack %s: %s", want, f)
		}
	}
	if got["203.0.0.1"].Found {
		t.Error("a host Censys didn't return is found")
	}
	wp, _ := json.Marshal(got["jssdk.juneworewyjyna.com"].Facts)
	for _, want := range []string{`"cert_names":["*.juneworewyjyna.com","juneworewyjyna.com"]`, `"cert_issuer":"Let's Encrypt"`, `"labels":["PHISHING"]`} {
		if !strings.Contains(string(wp), want) {
			t.Errorf("web property facts lack %s: %s", want, wp)
		}
	}

	// Bulk not allowed on the account: the same call falls back to one at
	// a time, and stays that way.
	bulkAllowed.Store(false)
	bulk.Store(0)
	single.Store(0)
	p2 := NewCensys(srv.URL, "t0ken")
	noWait(&p2.http, nil)
	a, _, err = p2.Lookup(context.Background(), []string{"185.242.226.118", "203.0.0.1"})
	if err != nil || len(a) != 2 || bulk.Load() != 1 || single.Load() != 2 {
		t.Errorf("fallback: %+v %v bulk %d single %d", a, err, bulk.Load(), single.Load())
	}
	p2.Lookup(context.Background(), []string{"185.242.226.118", "203.0.0.1"})
	if bulk.Load() != 1 {
		t.Error("tried bulk again after it was refused")
	}

	// A bad token stops it, and the token isn't in the error.
	bad := NewCensys(srv.URL, "s3cret-token")
	noWait(&bad.http, nil)
	_, _, err = bad.Lookup(context.Background(), []string{"185.242.226.118"})
	if !IsStop(err) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("bad token: %v", err)
	}
}

func TestGate(t *testing.T) {
	g := &Gate{LAN: map[string]bool{"2606:4700:10::5": true, "93.184.216.34": true}, Own: []string{"ourdomain.example"}}
	for ind, want := range map[string]bool{
		"185.242.226.118":            true,
		"8.8.8.8":                    true,
		"192.168.1.20":               false, // private
		"100.64.1.1":                 false, // CGNAT
		"192.0.0.170":                false, // NAT64 discovery
		"203.0.113.9":                false, // documentation
		"2001:db8::1":                false, // documentation
		"2606:4700:10::5":            false, // a LAN device's global IPv6
		"93.184.216.34":              false, // public, but a LAN device's
		"::ffff:192.168.1.20":        false,
		"jssdk.juneworewyjyna.com":   true,
		"mac":                        false, // single label
		"printer.lan":                false,
		"1.0.168.192.in-addr.arpa":   false,
		"ipv4only.arpa":              false,
		"ourdomain.example":          false, // ours
		"jellyfin.ourdomain.example": false, // ours
		"notourdomain.example":       true,
	} {
		if ok, why := g.Allow(ind); ok != want {
			t.Errorf("Allow(%s) = %v (%s), want %v", ind, ok, why, want)
		}
	}
	// Not loaded: refuse everything.
	var none Gate
	if ok, _ := none.Allow("8.8.8.8"); ok {
		t.Error("an unloaded gate let something through")
	}
}
