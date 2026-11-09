package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/forensics"
	"github.com/andrewalexander/ye-olde-monitoring/internal/server"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
	"github.com/andrewalexander/ye-olde-monitoring/middleware"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	st    *store.Store
	srv   *server.Server
	rec   *forensics.Recorder
	clock *clock
	h     http.Handler
}

func setup(t *testing.T, cfg server.Config) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	rec := forensics.New(st, io.Discard)
	rec.Resolve = nil
	t.Cleanup(rec.Close)
	cfg.Store, cfg.Now, cfg.OnTrip, cfg.OnEnd = st, c.Now, rec.OnTrip, rec.OnEnd
	srv := server.New(cfg)
	return &env{st: st, srv: srv, rec: rec, clock: c, h: srv.Public()}
}

func (e *env) do(method, url, ip string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	r.RemoteAddr = ip + ":40000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.st.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// page is a hit the visitor counter sees: a caddy GET of path.
func page(site, ip, path string, status int, ts time.Time) hit.Hit {
	return hit.Hit{Hash: hit.NewID(), TS: ts, Site: site, Source: "caddy", ClientIP: ip,
		Method: "GET", Path: path, Status: status}
}

func (e *env) counter(t *testing.T, site string) string {
	t.Helper()
	w := e.do("GET", "/counter.txt?site="+site, "203.0.113.9", "", nil)
	if w.Code != 200 {
		t.Fatalf("counter.txt?site=%s: %d", site, w.Code)
	}
	return strings.TrimSpace(w.Body.String())
}

// The counter is one per IP per UTC day that loaded a page, whatever
// recorded it, and the counter endpoints never write anything.
func TestCounterIsVisitorsFromHits(t *testing.T) {
	e := setup(t, server.Config{CounterSites: []string{"a", "b"}})
	day := e.clock.Now()
	ins := func(hs ...hit.Hit) {
		t.Helper()
		if _, err := e.st.InsertHits(hs); err != nil {
			t.Fatal(err)
		}
	}
	ins(
		page("a", "10.0.0.1", "/", 200, day),
		page("a", "10.0.0.1", "/", 200, day.Add(time.Minute)),        // reload: same visitor
		page("a", "10.0.0.1", "/about", 304, day.Add(2*time.Minute)), // another page, same day
		page("a", "10.0.0.1", "/", 200, day.Add(24*time.Hour)),       // next day: counts again
		page("a", "10.0.0.2", "/posts/", 200, day),
		page("a", "10.0.0.3", "/x.html", 200, day),
		page("a", "10.0.0.4", "/style.css", 200, day),    // asset
		page("a", "10.0.0.5", "/wp-login.php", 404, day), // probe
		page("a", "10.0.0.6", "/counter.svg", 200, day),  // the counter itself
		page("b", "10.0.0.7", "/", 200, day),
	)
	post := page("a", "10.0.0.8", "/", 200, day)
	post.Method = "POST"
	mw := page("a", "10.0.0.1", "/", 200, day) // the same visit, also sent by middleware
	mw.Source = "middleware"
	ins(post, mw)

	before := e.count(t, `SELECT count(*) FROM hits`)
	if got := e.counter(t, "a"); got != "4" {
		t.Errorf("a = %s, want 4 (10.0.0.1 twice, .2, .3)", got)
	}
	if got := e.counter(t, "b"); got != "1" {
		t.Errorf("b = %s, want 1", got)
	}
	svg := e.do("GET", "/counter.svg?site=a", "10.0.0.1", "", nil)
	if ct := svg.Header().Get("Content-Type"); ct != "image/svg+xml" || !strings.Contains(svg.Body.String(), `aria-label="4 visitors"`) {
		t.Errorf("svg response: %s %q", ct, svg.Body.String())
	}
	if after := e.count(t, `SELECT count(*) FROM hits`); after != before {
		t.Errorf("counter requests wrote %d hits", after-before)
	}
}

func TestCounterAllowlistAndCache(t *testing.T) {
	e := setup(t, server.Config{CounterSites: []string{"a"}, CounterTTL: time.Minute})
	for _, site := range []string{"other", "../etc", ""} {
		if w := e.do("GET", "/counter.svg?site="+site, "10.0.0.1", "", nil); w.Code != 404 {
			t.Errorf("site %q: %d, want 404", site, w.Code)
		}
	}
	if got := e.counter(t, "a"); got != "0" {
		t.Fatalf("empty = %s", got)
	}
	e.st.InsertHits([]hit.Hit{page("a", "10.0.0.1", "/", 200, e.clock.Now())})
	if got := e.counter(t, "a"); got != "0" {
		t.Errorf("within the TTL = %s, want the cached 0", got)
	}
	e.clock.Add(time.Minute)
	if got := e.counter(t, "a"); got != "1" {
		t.Errorf("after the TTL = %s, want 1", got)
	}
	// Nothing configured: the counter is off.
	off := setup(t, server.Config{})
	if w := off.do("GET", "/counter.txt?site=a", "10.0.0.1", "", nil); w.Code != 404 {
		t.Errorf("no CounterSites: %d, want 404", w.Code)
	}
}

func batchJSON(hits ...hit.Hit) string {
	b, _ := json.Marshal(middleware.IngestBatch{Hits: hits})
	return string(b)
}

func goodHit(id string, ts time.Time) hit.Hit {
	return hit.Hit{Hash: id, TS: ts, Site: "blog", Source: "middleware", ClientIP: "203.0.113.50",
		Method: "GET", Path: "/", Status: 200}
}

var auth = map[string]string{"Authorization": "Bearer sekrit", "Content-Type": "application/json"}

func TestIngestStatuses(t *testing.T) {
	e := setup(t, server.Config{Token: "sekrit", IngestBadPerMinute: 100})
	now := e.clock.Now()
	ip := "192.0.2.10"

	w := e.do("POST", "/ingest", ip, batchJSON(goodHit("a", now), goodHit("b", now)), auth)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"accepted": 2`) {
		t.Fatalf("good batch: %d %s", w.Code, w.Body)
	}
	// Retrying the same batch is harmless.
	w = e.do("POST", "/ingest", ip, batchJSON(goodHit("a", now), goodHit("b", now)), auth)
	if !strings.Contains(w.Body.String(), `"duplicates": 2`) {
		t.Errorf("retry: %s", w.Body)
	}
	if n := e.count(t, `SELECT count(*) FROM hits WHERE site = 'blog'`); n != 2 {
		t.Errorf("hits after retry = %d, want 2", n)
	}

	cases := []struct {
		name string
		body string
		hdr  map[string]string
		code int
	}{
		{"no token", batchJSON(goodHit("c", now)), nil, 401},
		{"wrong token", batchJSON(goodHit("c", now)), map[string]string{"Authorization": "Bearer nope"}, 401},
		{"garbage", "{not json", auth, 400},
		{"unknown field", `{"hits":[],"extra":1}`, auth, 400},
		{"one bad hit rejects the batch", batchJSON(goodHit("c", now), hit.Hit{Hash: "d", TS: now, Site: "blog", ClientIP: "not-an-ip"}), auth, 400},
		{"future ts", batchJSON(goodHit("e", now.Add(time.Hour))), auth, 400},
		{"oversize", `{"hits":[` + strings.Repeat(" ", server.MaxBody) + `]}`, auth, 413},
	}
	for _, c := range cases {
		w := e.do("POST", "/ingest", ip, c.body, c.hdr)
		if w.Code != c.code {
			t.Errorf("%s: got %d (%s), want %d", c.name, w.Code, strings.TrimSpace(w.Body.String()), c.code)
		}
	}
	if w := e.do("GET", "/ingest", ip, "", auth); w.Code != 405 {
		t.Errorf("GET /ingest = %d", w.Code)
	}
	if n := e.count(t, `SELECT count(*) FROM hits`); n != 2 {
		t.Errorf("hits = %d after rejected batches, want 2 (no partial inserts)", n)
	}
	tooMany := make([]hit.Hit, server.MaxBatch+1)
	for i := range tooMany {
		tooMany[i] = goodHit(fmt.Sprint("m", i), now)
	}
	if w := e.do("POST", "/ingest", ip, batchJSON(tooMany...), auth); w.Code != 400 {
		t.Errorf("oversized batch = %d", w.Code)
	}
}

func TestIngestBreakerTripsAndRecovers(t *testing.T) {
	e := setup(t, server.Config{Token: "sekrit", IngestBadPerMinute: 5, Cooldown: 5 * time.Minute})
	attacker, friend := "198.51.100.66", "192.0.2.10"
	hdr := map[string]string{
		"Authorization": "Bearer guess-1", "Cookie": "session=abc123",
		"User-Agent": "evil-scanner/1.0", "X-Forwarded-For": "10.9.9.9",
	}
	for i := range 5 {
		if w := e.do("POST", "/ingest", attacker, "{garbage", map[string]string{"Authorization": "Bearer sekrit"}); w.Code != 400 && i < 4 {
			t.Fatalf("bad request %d got %d, want 400 before the trip", i, w.Code)
		}
	}
	// Tripped now: 429 with Retry-After, even for a well-formed request.
	const flood = 25
	for range flood {
		e.clock.Add(time.Second)
		w := e.do("POST", "/ingest", attacker, batchJSON(goodHit("x", e.clock.Now())), hdr)
		if w.Code != 429 || w.Header().Get("Retry-After") == "" {
			t.Fatalf("during trip got %d (Retry-After %q), want 429", w.Code, w.Header().Get("Retry-After"))
		}
	}
	// Someone else is unaffected.
	if w := e.do("POST", "/ingest", friend, batchJSON(goodHit("f", e.clock.Now())), auth); w.Code != 200 {
		t.Errorf("friend during attacker's trip = %d", w.Code)
	}
	// After cooldown the attacker gets real status codes again.
	e.clock.Add(5 * time.Minute)
	if w := e.do("POST", "/ingest", attacker, "{garbage", auth); w.Code != 400 {
		t.Errorf("after cooldown, garbage = %d, want 400", w.Code)
	}
	if w := e.do("POST", "/ingest", attacker, batchJSON(goodHit("y", e.clock.Now())), auth); w.Code != 200 {
		t.Errorf("after cooldown, good batch = %d, want 200", w.Code)
	}
	e.rec.Close()

	trips, err := e.st.Trips(store.TripFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(trips) != 1 {
		t.Fatalf("got %d trip rows, want exactly 1 for one sustained flood", len(trips))
	}
	tr, _ := e.st.Trip(trips[0].ID)
	if tr.Key != attacker || tr.Breaker != "ingest" || tr.Reason != "malformed" || tr.WindowBad != 5 {
		t.Errorf("trip = %+v", tr)
	}
	if tr.Suppressed != flood {
		t.Errorf("suppressed = %d, want %d", tr.Suppressed, flood)
	}
	if tr.EndedAt.IsZero() {
		t.Error("trip never ended")
	}
	var d struct {
		Trigger struct {
			RemoteAddr string              `json:"remote_addr"`
			ClientIP   string              `json:"client_ip"`
			Headers    map[string][]string `json:"headers"`
			Body       string              `json:"body_sample"`
			Problem    string              `json:"problem"`
		} `json:"trigger"`
		Samples     []map[string]any `json:"samples"`
		LateSamples []map[string]any `json:"late_samples"`
		History     *store.IPHistory `json:"history"`
		RateCurve   []int            `json:"rate_curve"`
	}
	if err := json.Unmarshal(tr.Detail, &d); err != nil {
		t.Fatalf("detail: %v\n%s", err, tr.Detail)
	}
	if d.Trigger.ClientIP != attacker || d.Trigger.RemoteAddr != attacker+":40000" ||
		d.Trigger.Body != "{garbage" || !strings.Contains(d.Trigger.Problem, "bad JSON") {
		t.Errorf("trigger = %+v", d.Trigger)
	}
	if len(d.Samples) != 10 { // 5 requests, each an allow + a bad sample
		t.Errorf("samples = %d, want 10", len(d.Samples))
	}
	if len(d.LateSamples) != 20 {
		t.Errorf("late samples = %d, want 20 (capped)", len(d.LateSamples))
	}
	if d.History == nil || len(d.RateCurve) != 10 {
		t.Errorf("history/curve missing: %+v %v", d.History, d.RateCurve)
	}
	// Late samples hold the suppressed requests' summaries, including the UA.
	if s, _ := d.LateSamples[0]["data"].(string); !strings.Contains(s, "evil-scanner/1.0") || !strings.Contains(s, "10.9.9.9") {
		t.Errorf("late sample = %v", d.LateSamples[0])
	}
}

func TestTripRecordsAllHeadersButHashesSecrets(t *testing.T) {
	e := setup(t, server.Config{Token: "sekrit", IngestBadPerMinute: 1})
	hdr := map[string]string{
		"Authorization": "Bearer guess-1", "Cookie": "session=abc123",
		"User-Agent": "evil-scanner/1.0", "X-Forwarded-For": "10.9.9.9", "X-Custom": "anything",
	}
	if w := e.do("POST", "/ingest", "198.51.100.66", "{}", hdr); w.Code != 401 {
		t.Fatalf("got %d, want 401", w.Code)
	}
	e.rec.Close()
	trips, _ := e.st.Trips(store.TripFilter{})
	if len(trips) != 1 || trips[0].Reason != "bad_token" {
		t.Fatalf("trips = %+v", trips)
	}
	tr, _ := e.st.Trip(trips[0].ID)
	detail := string(tr.Detail)
	for _, secret := range []string{"guess-1", "abc123"} {
		if strings.Contains(detail, secret) {
			t.Errorf("detail contains secret %q", secret)
		}
	}
	for _, want := range []string{"evil-scanner/1.0", "10.9.9.9", "X-Custom", "anything",
		server.Fingerprint("Bearer guess-1"), server.Fingerprint("session=abc123")} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing %q:\n%s", want, detail)
		}
	}
}

func TestReadRoutes(t *testing.T) {
	e := setup(t, server.Config{Token: "sekrit"})
	e.do("POST", "/ingest", "192.0.2.10", batchJSON(goodHit("a", e.clock.Now()), goodHit("b", e.clock.Now())), auth)
	mux := http.NewServeMux()
	for pattern, h := range server.ReadRoutes(server.RouteConfig{Store: e.st, Now: e.clock.Now}) {
		mux.HandleFunc(pattern, h)
	}
	get := func(url string) (int, string) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		return w.Code, w.Body.String()
	}
	if code, body := get("/api/hits?ip=203.0.113.50"); code != 200 || !strings.Contains(body, `"203.0.113.50"`) {
		t.Errorf("hits: %d %s", code, body)
	}
	for _, url := range []string{"/api/hits?status=abc", "/api/hits?since=nonsense"} {
		if code, _ := get(url); code != 400 {
			t.Errorf("%s = %d, want 400", url, code)
		}
	}
	if code, _ := get("/api/trips/999"); code != 404 {
		t.Errorf("missing trip = %d", code)
	}
}

// The admin listener only answers health: the read routes are the explorer's.
func TestAdminHealth(t *testing.T) {
	e := setup(t, server.Config{Token: "sekrit"})
	admin := e.srv.Admin()
	get := func(url string) (int, string) {
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		return w.Code, w.Body.String()
	}
	if code, body := get("/api/health"); code != 200 || !strings.Contains(body, `"ingest"`) || !strings.Contains(body, `"data_problems"`) {
		t.Errorf("health: %d %s", code, body)
	}
	if code, _ := get("/api/hits"); code != 404 {
		t.Errorf("admin /api/hits = %d, want 404", code)
	}
}

// GET /api is the endpoint reference; it should mention every route.
func TestAPIDoc(t *testing.T) {
	e := setup(t, server.Config{})
	admin := e.srv.Admin()
	for _, url := range []string{"/api", "/api/"} {
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("%s: %d %s", url, w.Code, w.Header().Get("Content-Type"))
		}
		for _, route := range []string{
			"/counter.svg", "/counter.txt", "POST /ingest", "/api/health",
		} {
			if !strings.Contains(w.Body.String(), route) {
				t.Errorf("%s doesn't document %s", url, route)
			}
		}
	}
}
