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

func TestCounterCountsMatchHits(t *testing.T) {
	e := setup(t, server.Config{CounterPerMinute: 1000})
	const n = 50
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := e.do("GET", "/counter.svg?site=a", fmt.Sprintf("10.0.0.%d", i%5+1), "", nil); w.Code != 200 {
				t.Errorf("status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	c, _ := e.st.Counter("a")
	hits := e.count(t, `SELECT count(*) FROM hits WHERE site = 'a' AND source = 'counter'`)
	if c != n || hits != n {
		t.Errorf("counter = %d, hits = %d, want both %d", c, hits, n)
	}

	w := e.do("GET", "/counter.txt?site=a&noinc=1", "10.0.0.1", "", nil)
	if strings.TrimSpace(w.Body.String()) != fmt.Sprint(n) {
		t.Errorf("noinc txt = %q", w.Body.String())
	}
	if c, _ := e.st.Counter("a"); c != n {
		t.Errorf("noinc changed the counter to %d", c)
	}
	e.do("GET", "/counter.svg?site=b", "10.0.0.1", "", nil)
	if c, _ := e.st.Counter("b"); c != 1 {
		t.Errorf("site b = %d, want 1", c)
	}
	if c, _ := e.st.Counter("a"); c != n {
		t.Errorf("site b bumped site a to %d", c)
	}
	svg := e.do("GET", "/counter.svg?site=a&noinc=1", "10.0.0.1", "", nil)
	if ct := svg.Header().Get("Content-Type"); ct != "image/svg+xml" || !strings.Contains(svg.Body.String(), "<svg") {
		t.Errorf("svg response: %s %q", ct, svg.Body.String()[:40])
	}
}

func TestCounterRateLimit(t *testing.T) {
	e := setup(t, server.Config{CounterPerMinute: 5})
	for range 20 {
		if w := e.do("GET", "/counter.svg?site=a", "203.0.113.5", "", nil); w.Code != 200 {
			t.Fatalf("over-limit request got %d; should still get the image", w.Code)
		}
	}
	if c, _ := e.st.Counter("a"); c != 5 {
		t.Errorf("one IP pumped the counter to %d, want 5", c)
	}
	e.do("GET", "/counter.svg?site=a", "198.51.100.1", "", nil)
	if c, _ := e.st.Counter("a"); c != 6 {
		t.Errorf("other IP blocked: counter %d, want 6", c)
	}
	if w := e.do("GET", "/counter.svg?site=../etc", "198.51.100.1", "", nil); w.Code != 400 {
		t.Errorf("bad site got %d", w.Code)
	}
}

func batchJSON(hits ...hit.Hit) string {
	b, _ := json.Marshal(middleware.IngestBatch{Hits: hits})
	return string(b)
}

func goodHit(id string, ts time.Time) hit.Hit {
	return hit.Hit{Hash: id, TS: ts, Site: "blog", Source: "middleware", ClientIP: "203.0.113.50",
		Method: "GET", Path: "/", Status: 200, Count: true}
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
	if c, _ := e.st.Counter("blog"); c != 2 {
		t.Errorf("counter after retry = %d, want 2", c)
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

func TestAdminAPI(t *testing.T) {
	e := setup(t, server.Config{Token: "sekrit"})
	e.do("POST", "/ingest", "192.0.2.10", batchJSON(goodHit("a", e.clock.Now()), goodHit("b", e.clock.Now())), auth)
	admin := e.srv.Admin(nil)
	get := func(url string) (int, string) {
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		return w.Code, w.Body.String()
	}
	if code, body := get("/api/top?by=ip"); code != 200 || !strings.Contains(body, `"key": "203.0.113.50"`) || !strings.Contains(body, `"count": 2`) {
		t.Errorf("top: %d %s", code, body)
	}
	for _, url := range []string{"/api/top?by=password", "/api/dns/top?by=password", "/api/top?order=sideways"} {
		if code, _ := get(url); code != 400 {
			t.Errorf("%s = %d, want 400", url, code)
		}
	}
	if code, body := get("/api/top?by=ip&order=bottom&ip=192.0.2.99"); code != 200 || strings.Contains(body, "203.0.113.50") {
		t.Errorf("ip filter: %d %s", code, body)
	}
	if code, body := get("/api/top?by=ip,method"); code != 200 || !strings.Contains(body, `"keys"`) {
		t.Errorf("by= list: %d %s", code, body)
	}
	if code, body := get("/api/top?by=ip,method"); code != 200 || !strings.Contains(body, `"total": 2`) {
		t.Errorf("total: %d %s", code, body)
	}
	if code, body := get("/api/top?by=ip&status=4xx"); code != 200 || strings.Contains(body, "203.0.113.50") {
		t.Errorf("status filter: %d %s", code, body)
	}
	for _, url := range []string{"/api/top?status=abc", "/api/hits?status=abc"} {
		if code, _ := get(url); code != 400 {
			t.Errorf("%s = %d, want 400", url, code)
		}
	}
	if code, _ := get("/api/top?by=ip,password"); code != 400 {
		t.Errorf("bad by= in a list = %d", code)
	}
	if code, body := get("/api/top?by=ip&order=new"); code != 200 || !strings.Contains(body, `"first"`) {
		t.Errorf("order=new: %d %s", code, body)
	}
	if code, _ := get("/api/hits?since=nonsense"); code != 400 {
		t.Errorf("bad since = %d", code)
	}
	if code, _ := get("/api/trips/999"); code != 404 {
		t.Errorf("missing trip = %d", code)
	}
	if code, body := get("/api/health"); code != 200 || !strings.Contains(body, `"ingest"`) {
		t.Errorf("health: %d %s", code, body)
	}
}

// GET /api is the endpoint reference; it should mention every route.
func TestAPIDoc(t *testing.T) {
	e := setup(t, server.Config{})
	admin := e.srv.Admin(nil)
	for _, url := range []string{"/api", "/api/"} {
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("%s: %d %s", url, w.Code, w.Header().Get("Content-Type"))
		}
		for _, route := range []string{
			"/counter.svg", "/counter.txt", "/counter.js", "POST /ingest",
			"/api/hits", "/api/top", "/api/dns?domain", "/api/dns?client", "/api/dns/top",
			"/api/alerts?", "/api/bans?", "/api/trips?", "/api/trips/{id}", "/api/health",
		} {
			if !strings.Contains(w.Body.String(), route) {
				t.Errorf("%s doesn't document %s", url, route)
			}
		}
	}
}
