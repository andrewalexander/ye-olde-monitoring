// Package forensics writes circuit-breaker trips to the database with
// everything known about the offender at that moment. It does the work on
// one background goroutine so a flood can't turn forensics into its own
// denial of service: each trip is one row, written once.
package forensics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"dnscount/breaker"
	"dnscount/store"
)

type job struct {
	end  bool
	trip breaker.Trip
}

type Recorder struct {
	st  *store.Store
	log *log.Logger
	// Resolve does reverse DNS; nil disables it (tests).
	Resolve func(ctx context.Context, ip string) ([]string, error)

	mu      sync.Mutex
	closed  bool
	jobs    chan job
	ids     map[string]int64 // breaker/seq -> row id
	pending map[string]breaker.Trip
	wg      sync.WaitGroup
}

// New starts a recorder writing to st. Anything it can't store is written as
// JSON to errLog instead so nothing is lost.
func New(st *store.Store, errLog io.Writer) *Recorder {
	r := &Recorder{
		st:      st,
		log:     log.New(errLog, "forensics: ", log.LstdFlags),
		Resolve: net.DefaultResolver.LookupAddr,
		jobs:    make(chan job, 256),
		ids:     map[string]int64{},
		pending: map[string]breaker.Trip{},
	}
	r.wg.Add(1)
	go r.loop()
	return r
}

// OnTrip and OnEnd plug into breaker.Config.
func (r *Recorder) OnTrip(t breaker.Trip) { r.send(job{trip: t}) }
func (r *Recorder) OnEnd(t breaker.Trip)  { r.send(job{end: true, trip: t}) }

func (r *Recorder) send(j job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		r.dump("recorder closed", j.trip, nil)
		return
	}
	select {
	case r.jobs <- j:
	default:
		r.dump("queue full", j.trip, nil)
	}
}

// Close drains the queue and waits for it to be written.
func (r *Recorder) Close() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.jobs)
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *Recorder) loop() {
	defer r.wg.Done()
	for j := range r.jobs {
		k := fmt.Sprintf("%s/%d", j.trip.Breaker, j.trip.Seq)
		if !j.end {
			r.record(k, j.trip)
			if end, ok := r.pending[k]; ok {
				delete(r.pending, k)
				r.finish(k, end)
			}
			continue
		}
		if _, ok := r.ids[k]; !ok {
			r.pending[k] = j.trip // end arrived before its trip; finish later
			continue
		}
		r.finish(k, j.trip)
	}
}

// Detail is what goes in breaker_trips.detail_json.
type Detail struct {
	Trigger     any               `json:"trigger,omitempty"`
	Samples     []breaker.Sample  `json:"samples"`
	RateCurve   []int             `json:"rate_curve"`
	ReverseDNS  []string          `json:"reverse_dns,omitempty"`
	History     *store.IPHistory  `json:"history,omitempty"`
	LateSamples []breaker.Sample  `json:"late_samples,omitempty"`
	Notes       map[string]string `json:"notes,omitempty"`
}

func (r *Recorder) record(k string, t breaker.Trip) {
	d := Detail{Trigger: t.Trigger, Samples: t.Samples, RateCurve: t.Curve, Notes: map[string]string{}}
	if _, err := netip.ParseAddr(t.Key); err == nil {
		if r.Resolve != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			names, err := r.Resolve(ctx, t.Key)
			cancel()
			if err != nil {
				d.Notes["reverse_dns"] = err.Error()
			}
			d.ReverseDNS = names
		}
		if h, err := r.st.IPHistory(t.Key); err == nil {
			d.History = &h
		} else {
			d.Notes["history"] = err.Error()
		}
	}
	if len(d.Notes) == 0 {
		d.Notes = nil
	}
	blob, err := json.Marshal(d)
	if err != nil {
		blob, _ = json.Marshal(map[string]string{"marshal_error": err.Error(), "trigger": fmt.Sprint(t.Trigger)})
	}
	id, err := r.st.InsertTrip(store.Trip{
		TrippedAt: t.TrippedAt, CooldownUntil: t.CooldownUntil, Breaker: t.Breaker, Key: t.Key,
		Reason: t.Reason, WindowEvents: t.WindowEvents, WindowBad: t.WindowBad, FirstSeen: t.FirstSeen,
		Detail: blob,
	})
	if err != nil {
		r.dump(err.Error(), t, blob)
		return
	}
	r.ids[k] = id
	r.log.Printf("%s tripped by %s (%s): %d events, %d bad in window; trip #%d",
		t.Breaker, t.Key, t.Reason, t.WindowEvents, t.WindowBad, id)
}

func (r *Recorder) finish(k string, t breaker.Trip) {
	id := r.ids[k]
	delete(r.ids, k)
	late, _ := json.Marshal(t.LateSamples)
	if err := r.st.EndTrip(id, t.EndedAt, t.Suppressed, late); err != nil {
		r.dump(err.Error(), t, nil)
		return
	}
	r.log.Printf("%s trip #%d for %s ended; %d suppressed during cooldown", t.Breaker, id, t.Key, t.Suppressed)
}

func (r *Recorder) dump(why string, t breaker.Trip, detail json.RawMessage) {
	b, _ := json.Marshal(struct {
		Why    string          `json:"why"`
		Trip   breaker.Trip    `json:"trip"`
		Detail json.RawMessage `json:"detail,omitempty"`
	}{why, t, detail})
	r.log.Printf("could not store trip: %s", b)
}
