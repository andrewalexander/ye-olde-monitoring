// Package guard is a dumb fixed-window circuit breaker keyed by client
// (usually an IP). A key trips when it sends too many events, too many bad
// events, or too high a ratio of bad events in one window; it is then
// rejected until its cooldown ends. Each key keeps a small ring buffer of
// recent events so that when it trips we have evidence, not just the last
// request.
package guard

import (
	"context"
	"sync"
	"time"
)

// Event is one thing a key did.
type Event struct {
	// Data is a short summary kept in the ring buffer (capped at SampleSize).
	Data string
	// Trigger is the full detail of this event. It's only kept if this event
	// is the one that trips the breaker, so it can be large.
	Trigger any
}

// Sample is a ring-buffer entry.
type Sample struct {
	TS     time.Time `json:"ts"`
	Bad    bool      `json:"bad,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Data   string    `json:"data"`
}

// Trip describes one trip. OnTrip and OnEnd get copies, so they can keep or
// use them freely.
type Trip struct {
	Seq           uint64 // unique per Breaker; pairs OnTrip with OnEnd
	Breaker       string
	Key           string
	Reason        string // rate|malformed|oversize|bad_token|not_allowed|map_full|...
	TrippedAt     time.Time
	CooldownUntil time.Time
	EndedAt       time.Time
	FirstSeen     time.Time // start of the window that tripped
	WindowEvents  int
	WindowBad     int
	Suppressed    int   // events rejected during cooldown
	Curve         []int // events per tenth of the window
	Samples       []Sample
	LateSamples   []Sample // first few events rejected during cooldown
	Trigger       any
}

// Global is the key used when the key map is full and everything trips.
const Global = "*"

const curveBuckets = 10

type Config struct {
	Name     string
	Window   time.Duration
	Cooldown time.Duration
	// Max events per key per window; 0 means unlimited.
	Max int
	// MaxBad bad events per key per window trips it; 0 means never.
	MaxBad int
	// BadRatio trips a key once it has at least MinEvents events in the
	// window and more than this fraction of them were bad; 0 disables.
	BadRatio  float64
	MinEvents int
	// MaxKeys caps memory; when full, a new key trips Global (everyone is
	// rejected for a cooldown) so a spoofed-address flood can't grow the map.
	MaxKeys    int
	Samples    int // ring buffer size per key
	SampleSize int // bytes kept per sample
	Now        func() time.Time
	OnTrip     func(Trip)
	OnEnd      func(Trip)
}

type state struct {
	start    time.Time
	events   int
	bad      int
	curve    [curveBuckets]int
	lastSeen time.Time
	ring     []Sample
	ringNext int
	trip     *Trip
}

type Breaker struct {
	cfg       Config
	mu        sync.Mutex
	keys      map[string]*state
	global    *state
	seq       uint64
	lastSweep time.Time
	trips     int
	suppr     int
}

func New(cfg Config) *Breaker {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxKeys == 0 {
		cfg.MaxKeys = 10000
	}
	if cfg.Samples == 0 {
		cfg.Samples = 20
	}
	if cfg.SampleSize == 0 {
		cfg.SampleSize = 4096
	}
	return &Breaker{cfg: cfg, keys: map[string]*state{}}
}

// Allow records an event for key and reports whether it may proceed.
func (b *Breaker) Allow(key string, ev Event) bool {
	var fire []func()
	defer func() { run(fire) }()
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	st, ok := b.get(key, now, ev, &fire)
	if !ok {
		return false
	}
	st.events++
	st.curve[b.bucket(st, now)]++
	b.sample(st, now, false, "", ev.Data)
	if b.cfg.Max > 0 && st.events > b.cfg.Max {
		b.trip(st, key, "rate", now, ev.Trigger, &fire)
		return false
	}
	return true
}

// Bad records a malformed/unauthorized event for key with a reason, and
// reports whether key is now tripped. Callers should only call Bad for
// events Allow let through (or that never went through Allow, like a
// rejected source), so nothing is counted twice.
func (b *Breaker) Bad(key, reason string, ev Event) bool {
	var fire []func()
	defer func() { run(fire) }()
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	st, ok := b.get(key, now, ev, &fire)
	if !ok {
		return true
	}
	st.bad++
	b.sample(st, now, true, reason, ev.Data)
	c := b.cfg
	if (c.MaxBad > 0 && st.bad >= c.MaxBad) ||
		(c.BadRatio > 0 && st.events >= c.MinEvents && float64(st.bad) > c.BadRatio*float64(st.events)) {
		b.trip(st, key, reason, now, ev.Trigger, &fire)
		return true
	}
	return false
}

// get returns key's state ready to count an event, or false if the event is
// rejected (key or Global in cooldown). Rejections are counted as suppressed.
func (b *Breaker) get(key string, now time.Time, ev Event, fire *[]func()) (*state, bool) {
	if now.Sub(b.lastSweep) >= b.cfg.Window {
		b.sweep(now, fire)
	}
	if g := b.global; g != nil {
		if now.Before(g.trip.CooldownUntil) {
			b.suppress(g, now, ev)
			return nil, false
		}
		b.end(g, fire)
		b.global = nil
	}
	st := b.keys[key]
	if st == nil {
		if len(b.keys) >= b.cfg.MaxKeys {
			b.sweep(now, fire)
		}
		if len(b.keys) >= b.cfg.MaxKeys {
			g := &state{start: now, events: 1, lastSeen: now}
			b.sample(g, now, false, "", ev.Data)
			b.global = g
			b.trip(g, Global, "map_full", now, ev.Trigger, fire)
			return nil, false
		}
		st = &state{start: now}
		b.keys[key] = st
	}
	if st.trip != nil {
		if now.Before(st.trip.CooldownUntil) {
			b.suppress(st, now, ev)
			return nil, false
		}
		b.end(st, fire)
	}
	if now.Sub(st.start) >= b.cfg.Window {
		st.start, st.events, st.bad, st.curve = now, 0, 0, [curveBuckets]int{}
	}
	st.lastSeen = now
	return st, true
}

func (b *Breaker) bucket(st *state, now time.Time) int {
	i := int(now.Sub(st.start) * curveBuckets / b.cfg.Window)
	return min(max(i, 0), curveBuckets-1)
}

func (b *Breaker) sample(st *state, now time.Time, bad bool, reason, data string) {
	if len(data) > b.cfg.SampleSize {
		data = data[:b.cfg.SampleSize]
	}
	s := Sample{TS: now, Bad: bad, Reason: reason, Data: data}
	if len(st.ring) < b.cfg.Samples {
		st.ring = append(st.ring, s)
		return
	}
	st.ring[st.ringNext] = s
	st.ringNext = (st.ringNext + 1) % len(st.ring)
}

func (b *Breaker) trip(st *state, key, reason string, now time.Time, trigger any, fire *[]func()) {
	b.seq++
	b.trips++
	samples := make([]Sample, 0, len(st.ring))
	samples = append(samples, st.ring[st.ringNext:]...)
	samples = append(samples, st.ring[:st.ringNext]...)
	st.trip = &Trip{
		Seq: b.seq, Breaker: b.cfg.Name, Key: key, Reason: reason,
		TrippedAt: now, CooldownUntil: now.Add(b.cfg.Cooldown), FirstSeen: st.start,
		WindowEvents: st.events, WindowBad: st.bad,
		Curve: append([]int(nil), st.curve[:]...), Samples: samples, Trigger: trigger,
	}
	if b.cfg.OnTrip != nil {
		t := copyTrip(st.trip)
		*fire = append(*fire, func() { b.cfg.OnTrip(t) })
	}
}

func (b *Breaker) suppress(st *state, now time.Time, ev Event) {
	st.trip.Suppressed++
	b.suppr++
	if len(st.trip.LateSamples) < b.cfg.Samples {
		data := ev.Data
		if len(data) > b.cfg.SampleSize {
			data = data[:b.cfg.SampleSize]
		}
		st.trip.LateSamples = append(st.trip.LateSamples, Sample{TS: now, Data: data})
	}
}

// end closes st's trip and starts it on a fresh window.
func (b *Breaker) end(st *state, fire *[]func()) {
	t := st.trip
	t.EndedAt = t.CooldownUntil
	if b.cfg.OnEnd != nil {
		c := copyTrip(t)
		*fire = append(*fire, func() { b.cfg.OnEnd(c) })
	}
	st.trip = nil
	st.start, st.events, st.bad, st.curve = t.CooldownUntil, 0, 0, [curveBuckets]int{}
}

// Sweep ends expired trips and forgets idle keys. It runs on its own during
// Allow/Bad; call it (or Run) so trips end even when traffic stops.
func (b *Breaker) Sweep() {
	var fire []func()
	b.mu.Lock()
	b.sweep(b.cfg.Now(), &fire)
	b.mu.Unlock()
	run(fire)
}

func (b *Breaker) sweep(now time.Time, fire *[]func()) {
	b.lastSweep = now
	if g := b.global; g != nil && !now.Before(g.trip.CooldownUntil) {
		b.end(g, fire)
		b.global = nil
	}
	for k, st := range b.keys {
		if st.trip != nil && !now.Before(st.trip.CooldownUntil) {
			b.end(st, fire)
		}
		if st.trip == nil && now.Sub(st.lastSeen) > 2*b.cfg.Window {
			delete(b.keys, k)
		}
	}
}

// Run sweeps every second until ctx is done.
func (b *Breaker) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Sweep()
		}
	}
}

// CooldownUntil reports when key (or Global) can send again, if it's tripped.
func (b *Breaker) CooldownUntil(key string) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	if g := b.global; g != nil && now.Before(g.trip.CooldownUntil) {
		return g.trip.CooldownUntil, true
	}
	if st := b.keys[key]; st != nil && st.trip != nil && now.Before(st.trip.CooldownUntil) {
		return st.trip.CooldownUntil, true
	}
	return time.Time{}, false
}

// Stats is a point-in-time view for health endpoints.
type Stats struct {
	Name       string `json:"name"`
	Trips      int    `json:"trips"`
	Suppressed int    `json:"suppressed"`
	Tripped    int    `json:"tripped_now"`
	Keys       int    `json:"keys"`
}

func (b *Breaker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := Stats{Name: b.cfg.Name, Trips: b.trips, Suppressed: b.suppr, Keys: len(b.keys)}
	for _, st := range b.keys {
		if st.trip != nil {
			s.Tripped++
		}
	}
	if b.global != nil {
		s.Tripped++
	}
	return s
}

func copyTrip(t *Trip) Trip {
	c := *t
	c.Curve = append([]int(nil), t.Curve...)
	c.Samples = append([]Sample(nil), t.Samples...)
	c.LateSamples = append([]Sample(nil), t.LateSamples...)
	return c
}

func run(fs []func()) {
	for _, f := range fs {
		f()
	}
}
