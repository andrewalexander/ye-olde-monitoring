package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnscount/hit"
	"dnscount/store"
)

type memSink struct {
	mu   sync.Mutex
	hits []hit.Hit
}

func (m *memSink) Record(h hit.Hit) { m.mu.Lock(); m.hits = append(m.hits, h); m.mu.Unlock() }

func TestWrapRecordsStatusAndBytes(t *testing.T) {
	sink := &memSink{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") })
	mux.HandleFunc("/teapot", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("short and stout"))
	})
	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {})
	proxy := netip.MustParsePrefix("10.0.0.0/8")
	h := Wrap(mux, sink, Options{Site: "s", SkipPaths: []string{"/healthz"}, TrustedProxies: []netip.Prefix{proxy}})

	for _, c := range []struct{ path, remote, xff string }{
		{"/ok?x=1", "203.0.113.1:5000", ""},
		{"/teapot", "10.0.0.2:5000", "198.51.100.9, 10.0.0.3"}, // via our proxies
		{"/empty", "203.0.113.1:5000", "6.6.6.6"},              // spoofed XFF from a direct client
		{"/healthz", "203.0.113.1:5000", ""},
	} {
		r := httptest.NewRequest("GET", c.path, nil)
		r.RemoteAddr = c.remote
		r.Header.Set("User-Agent", "test\x00agent")
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(sink.hits) != 3 {
		t.Fatalf("recorded %d hits, want 3 (healthz skipped)", len(sink.hits))
	}
	ok, tea, empty := sink.hits[0], sink.hits[1], sink.hits[2]
	if ok.Status != 200 || ok.Bytes != 5 || ok.Path != "/ok" || ok.Query != "x=1" || ok.ClientIP != "203.0.113.1" {
		t.Errorf("ok = %+v", ok)
	}
	if tea.Status != 418 || tea.Bytes != 15 || tea.ClientIP != "198.51.100.9" {
		t.Errorf("teapot = %+v", tea)
	}
	if empty.Status != 200 || empty.Bytes != 0 || empty.ClientIP != "203.0.113.1" || empty.ForwardedFor != "6.6.6.6" {
		t.Errorf("empty (spoofed XFF must not be believed) = %+v", empty)
	}
	if ok.UserAgent != "test?agent" {
		t.Errorf("control chars not stripped: %q", ok.UserAgent)
	}
	if ok.Hash == "" || ok.Hash == tea.Hash {
		t.Error("hits need distinct IDs")
	}
}

func TestLocalSinkWrites(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sink := NewLocalSink(st)
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), sink, Options{Site: "s", Count: true})
	for range 10 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}
	sink.Close()
	if n, _ := st.Counter("s"); n != 10 {
		t.Errorf("counter = %d, want 10", n)
	}
}

func TestSinkPausesAfterFailures(t *testing.T) {
	var n atomic.Int32
	calls := func() int { return int(n.Load()) }
	b := newBatcher(time.Hour, func([]hit.Hit) error { n.Add(1); return errors.New("collector down") })
	for range failAfter * batchSize {
		b.Record(hit.Hit{})
		for len(b.ch) > 0 { // let the loop take it so batches fill one at a time
			time.Sleep(time.Millisecond)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if calls() != failAfter {
		t.Fatalf("flush called %d times, want %d", calls(), failAfter)
	}
	s := b.Stats()
	if s.PausedUntil.IsZero() || s.LastError != "collector down" {
		t.Errorf("not paused after %d failures: %+v", failAfter, s)
	}
	before := s.Dropped
	b.Record(hit.Hit{}) // dropped immediately while paused, no flush attempted
	b.Close()
	if calls() != failAfter || b.Stats().Dropped != before+1 {
		t.Errorf("calls %d dropped %d, want %d and %d", calls(), b.Stats().Dropped, failAfter, before+1)
	}
}
