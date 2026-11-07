package guard

import (
	"fmt"
	"sync"
	"testing"
	"time"
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

type rec struct {
	trips, ends []Trip
}

func newTest(cfg Config) (*Breaker, *clock, *rec) {
	c := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	r := &rec{}
	cfg.Now = c.Now
	cfg.OnTrip = func(t Trip) { r.trips = append(r.trips, t) }
	cfg.OnEnd = func(t Trip) { r.ends = append(r.ends, t) }
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 5 * time.Minute
	}
	return New(cfg), c, r
}

func ev(i int) Event { return Event{Data: fmt.Sprintf("req %d", i), Trigger: map[string]int{"n": i}} }

func TestRateTripAndCooldown(t *testing.T) {
	b, c, r := newTest(Config{Name: "t", Max: 5})
	for i := range 5 {
		if !b.Allow("1.2.3.4", ev(i)) {
			t.Fatalf("event %d rejected under the limit", i)
		}
	}
	if b.Allow("1.2.3.4", ev(5)) {
		t.Fatal("6th event allowed over limit of 5")
	}
	if !b.Allow("5.6.7.8", ev(0)) {
		t.Fatal("other key affected by trip")
	}
	if len(r.trips) != 1 {
		t.Fatalf("got %d trips, want 1", len(r.trips))
	}
	tr := r.trips[0]
	if tr.Key != "1.2.3.4" || tr.Reason != "rate" || tr.WindowEvents != 6 || len(tr.Samples) != 6 {
		t.Errorf("trip = %+v", tr)
	}
	if tr.Samples[0].Data != "req 0" || tr.Samples[5].Data != "req 5" {
		t.Errorf("samples out of order: %+v", tr.Samples)
	}
	if tr.Trigger.(map[string]int)["n"] != 5 {
		t.Errorf("trigger should be the tripping event, got %v", tr.Trigger)
	}

	// Keep hammering through the cooldown: suppressed, and no new trip rows.
	for i := range 30 {
		c.Add(5 * time.Second)
		if b.Allow("1.2.3.4", ev(100+i)) {
			t.Fatalf("allowed during cooldown at +%ds", (i+1)*5)
		}
	}
	if len(r.trips) != 1 {
		t.Errorf("sustained flood produced %d trips during one cooldown, want 1", len(r.trips))
	}
	c.Add(5*time.Minute - 150*time.Second)
	if !b.Allow("1.2.3.4", ev(200)) {
		t.Fatal("still rejected after cooldown")
	}
	if len(r.ends) != 1 {
		t.Fatalf("got %d ends, want 1", len(r.ends))
	}
	end := r.ends[0]
	if end.Suppressed != 30 || len(end.LateSamples) != 20 || end.Seq != tr.Seq || !end.EndedAt.Equal(tr.CooldownUntil) {
		t.Errorf("end = suppressed %d, late %d, seq %d/%d, ended %v", end.Suppressed, len(end.LateSamples), end.Seq, tr.Seq, end.EndedAt)
	}
}

func TestOneTripPerCooldown(t *testing.T) {
	b, c, r := newTest(Config{Name: "t", Max: 2, Cooldown: time.Minute})
	for range 10 * 60 { // ten minutes of 1 req/s
		b.Allow("k", ev(0))
		c.Add(time.Second)
	}
	// Each cycle: 3 events to trip, then a minute of cooldown.
	if n := len(r.trips); n < 9 || n > 10 {
		t.Errorf("10 minutes of flood with 1m cooldown gave %d trips, want ~10", n)
	}
}

func TestBadTrips(t *testing.T) {
	b, _, r := newTest(Config{Name: "t", Max: 100, MaxBad: 3})
	for i := range 2 {
		b.Allow("k", ev(i))
		if b.Bad("k", "malformed", ev(i)) {
			t.Fatal("tripped before MaxBad")
		}
	}
	b.Allow("k", ev(2))
	if !b.Bad("k", "bad_token", ev(2)) {
		t.Fatal("not tripped at MaxBad")
	}
	if r.trips[0].Reason != "bad_token" || r.trips[0].WindowBad != 3 {
		t.Errorf("trip = %+v", r.trips[0])
	}
	if b.Allow("k", ev(3)) {
		t.Error("allowed after bad trip")
	}
}

func TestBadRatio(t *testing.T) {
	b, _, r := newTest(Config{Name: "t", BadRatio: 0.5, MinEvents: 10})
	for i := range 9 { // all bad but under MinEvents
		b.Allow("k", ev(i))
		b.Bad("k", "malformed", ev(i))
	}
	if len(r.trips) != 0 {
		t.Fatal("tripped under MinEvents")
	}
	b.Allow("k", ev(9))
	if !b.Bad("k", "malformed", ev(9)) {
		t.Fatal("10/10 bad did not trip")
	}
	// A mostly-good source stays up.
	for i := range 100 {
		b.Allow("good", ev(i))
		if i%4 == 0 && b.Bad("good", "malformed", ev(i)) {
			t.Fatal("25% bad tripped a 50% ratio")
		}
	}
}

func TestWindowResets(t *testing.T) {
	b, c, r := newTest(Config{Name: "t", Max: 5})
	for range 4 {
		for range 5 {
			if !b.Allow("k", ev(0)) {
				t.Fatal("rejected within limit")
			}
		}
		c.Add(time.Minute)
	}
	if len(r.trips) != 0 {
		t.Errorf("steady traffic under the limit tripped %d times", len(r.trips))
	}
}

func TestMapFullTripsGlobal(t *testing.T) {
	b, c, r := newTest(Config{Name: "t", Max: 100, MaxKeys: 3})
	for i := range 3 {
		if !b.Allow(fmt.Sprint(i), ev(i)) {
			t.Fatal("rejected before map full")
		}
	}
	if b.Allow("new", ev(9)) {
		t.Fatal("new key allowed with map full")
	}
	if len(r.trips) != 1 || r.trips[0].Key != Global || r.trips[0].Reason != "map_full" {
		t.Fatalf("trips = %+v", r.trips)
	}
	if b.Allow("0", ev(0)) {
		t.Error("existing key allowed during global trip")
	}
	if _, ok := b.CooldownUntil("anyone"); !ok {
		t.Error("CooldownUntil should report global trip")
	}
	c.Add(6 * time.Minute) // past cooldown and past idle expiry
	if !b.Allow("new", ev(0)) {
		t.Error("new key still rejected after cooldown and idle sweep")
	}
	if len(r.ends) != 1 {
		t.Errorf("global trip ends = %d", len(r.ends))
	}
}

func TestSweepEndsTripsWithoutTraffic(t *testing.T) {
	b, c, r := newTest(Config{Name: "t", Max: 1})
	b.Allow("k", ev(0))
	b.Allow("k", ev(1))
	c.Add(10 * time.Minute)
	b.Sweep()
	if len(r.ends) != 1 {
		t.Fatalf("sweep ended %d trips, want 1", len(r.ends))
	}
	if s := b.Stats(); s.Tripped != 0 || s.Keys != 0 || s.Trips != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestSampleSizeCap(t *testing.T) {
	b, _, r := newTest(Config{Name: "t", Max: 1, SampleSize: 8})
	b.Allow("k", Event{Data: "0123456789abcdef"})
	b.Allow("k", Event{Data: "x"})
	if got := r.trips[0].Samples[0].Data; got != "01234567" {
		t.Errorf("sample = %q, want capped to 8 bytes", got)
	}
}
