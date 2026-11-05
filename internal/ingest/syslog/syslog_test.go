package syslog

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/forensics"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

var router = netip.MustParseAddrPort("192.168.1.1:514")

func setup(t *testing.T, raw string) (*Listener, *store.Store, *forensics.Recorder) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rec := forensics.New(st, io.Discard)
	rec.Resolve = nil
	t.Cleanup(rec.Close)
	allow, _ := hit.ParsePrefixes("192.168.1.1")
	c := &clock{t: time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)}
	l, err := New(Config{Store: st, Allow: allow, RawDir: raw, Now: c.Now, OnTrip: rec.OnTrip, OnEnd: rec.OnEnd})
	if err != nil {
		t.Fatal(err)
	}
	return l, st, rec
}

func fixture(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/unifi-syslog.log")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func counts(t *testing.T, st *store.Store) (q, r, c int) {
	t.Helper()
	db := st.DB()
	db.QueryRow(`SELECT count(*) FROM dns_queries`).Scan(&q)
	db.QueryRow(`SELECT count(*) FROM dns_replies`).Scan(&r)
	db.QueryRow(`SELECT count(*) FROM connections`).Scan(&c)
	return
}

func TestRequiresAllowlist(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("started without an allowlist")
	}
}

func TestStoresAndReplayIsIdempotent(t *testing.T) {
	raw := t.TempDir()
	l, st, _ := setup(t, raw)
	for range 2 { // the router resending, or a replayed capture
		for _, line := range fixture(t) {
			l.HandleLine(router, "udp", line)
		}
		l.Flush()
	}
	l.Close()
	// The replay is a second copy of every line, so the deduper numbers them
	// as repeats: that's correct for live traffic (real repeats are real
	// lookups). Idempotency is about re-*ingesting* the same log, below.
	q, r, c := counts(t, st)
	if q != 2 || r != 2 || c != 4 {
		t.Errorf("live: queries=%d replies=%d conns=%d", q, r, c)
	}
	// Re-ingesting the raw file adds nothing: same lines, same order, same keys.
	files, _ := filepath.Glob(filepath.Join(raw, "*.log"))
	if len(files) != 1 {
		t.Fatalf("raw files = %v", files)
	}
	l2, _, _ := setup(t, "")
	l2.cfg.Store = st
	f, _ := os.Open(files[0])
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l2.HandleLine(router, "udp", sc.Text())
	}
	l2.Flush()
	if q2, r2, c2 := counts(t, st); q2 != q || r2 != r || c2 != c {
		t.Errorf("re-ingesting raw file changed counts: %d/%d/%d -> %d/%d/%d", q, r, c, q2, r2, c2)
	}
	if s := l.Stats(); s.Records != 8 || s.Skipped != 4 || s.Bad != 0 {
		t.Errorf("stats = %+v", s)
	}
}

func TestStrangerIsRejectedAndRecorded(t *testing.T) {
	l, st, rec := setup(t, "")
	stranger := netip.MustParseAddrPort("203.0.113.99:5555")
	for _, line := range fixture(t) {
		l.HandleLine(stranger, "udp", line)
	}
	l.Flush()
	rec.Close()
	if q, r, c := counts(t, st); q+r+c != 0 {
		t.Errorf("stored %d rows from a non-allowlisted source", q+r+c)
	}
	trips, _ := st.Trips(store.TripFilter{})
	if len(trips) != 1 || trips[0].Reason != "not_allowed" || trips[0].Key != "203.0.113.99" {
		t.Fatalf("trips = %+v", trips)
	}
	tr, _ := st.Trip(trips[0].ID)
	if !strings.Contains(string(tr.Detail), "evil.example.org") || !strings.Contains(string(tr.Detail), `"source_port":5555`) {
		t.Errorf("detail lacks the offending line/port: %s", tr.Detail)
	}
	if l.Stats().Rejected != 6 {
		t.Errorf("rejected = %d, want 6", l.Stats().Rejected)
	}
}

func TestGarbageFloodTripsOnlyThatSource(t *testing.T) {
	allow, _ := hit.ParsePrefixes("192.168.1.0/24")
	l, st, rec := setup(t, "")
	l.cfg.Allow = allow
	bad := netip.MustParseAddrPort("192.168.1.66:514")
	for range 40 {
		l.HandleLine(bad, "udp", "<30>Oct 28 09:00:00 x dnsmasq[1]: query[A] no-from-clause")
	}
	for _, line := range fixture(t) {
		l.HandleLine(router, "udp", line)
	}
	// The flooding source is now ignored even for good lines.
	for _, line := range fixture(t) {
		l.HandleLine(bad, "udp", line)
	}
	l.Flush()
	rec.Close()
	q, _, c := counts(t, st)
	if q != 1 || c != 2 {
		t.Errorf("queries=%d conns=%d, want only the router's 1 and 2", q, c)
	}
	trips, _ := st.Trips(store.TripFilter{})
	if len(trips) != 1 || trips[0].Key != "192.168.1.66" || trips[0].Reason != "malformed" {
		t.Errorf("trips = %+v", trips)
	}
}

func TestOversizeLine(t *testing.T) {
	l, _, _ := setup(t, "")
	l.HandleLine(router, "udp", "<30>Oct 28 09:00:00 x dnsmasq[1]: "+strings.Repeat("a", MaxLine))
	if l.Stats().Bad != 1 {
		t.Errorf("oversize line not counted bad: %+v", l.Stats())
	}
}

func TestUDPEndToEnd(t *testing.T) {
	l, st, _ := setup(t, "")
	l.cfg.Allow, _ = hit.ParsePrefixes("127.0.0.1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- l.Listen(ctx, []string{"udp://" + addr}) }()
	time.Sleep(100 * time.Millisecond)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range fixture(t) {
		conn.Write([]byte(line))
	}
	conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if q, _, c := counts(t, st); q == 1 && c == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP lines never landed: %+v", l.Stats())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
}
