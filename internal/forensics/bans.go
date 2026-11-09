package forensics

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/f2b"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// BanDetail is what goes in ban_forensics.detail_json: for a fail2ban ban
// (or an exempt address fail2ban would have banned), the same kinds of
// evidence a trip's Detail keeps. There's no reverse DNS: whatever records
// bans runs offline.
type BanDetail struct {
	Event    string `json:"event"` // ban | ignored
	Jail     string `json:"jail"`
	MaxRetry int    `json:"maxretry"`
	FindTime int64  `json:"findtime_s"`
	// Found is when fail2ban matched each line that led to the ban.
	Found []time.Time `json:"found"`
	// Trigger is those lines as we stored them: the requests (and refused
	// logins) from the address at each found time.
	Trigger *BanTrigger `json:"trigger,omitempty"`
	// Samples are its last requests up to the ban, oldest first: the
	// counterpart of a trip's ring buffer.
	Samples []hit.Hit `json:"samples"`
	// RateCurve is its requests per tenth of the jail's findtime before the
	// ban.
	RateCurve []int            `json:"rate_curve"`
	History   *store.IPHistory `json:"history,omitempty"`
	// RestoredOf: fail2ban re-applied this ban after a restart; the
	// evidence is on that ban.
	RestoredOf int64 `json:"restored_of,omitempty"`
	// Backfilled: recorded well after the ban, from what was stored. Rows
	// are kept, and History counts only what came before the ban, so it
	// matches what would have been recorded then.
	Backfilled bool `json:"backfilled,omitempty"`
	// During is filled in after the unban: what it kept sending.
	During *BanDuring        `json:"during,omitempty"`
	Notes  map[string]string `json:"notes,omitempty"`
}

// BanTrigger is the stored lines that made fail2ban act.
type BanTrigger struct {
	Hits   []hit.Hit           `json:"hits,omitempty"`
	Logins []store.AuthFailure `json:"logins,omitempty"`
}

// BanDuring is what a banned address did while the ban was in force: the
// counterpart of a trip's suppressed count and late samples.
type BanDuring struct {
	Until time.Time `json:"until"`
	store.BlockedTraffic
	// Leaked is requests that still reached a site on a port the ban
	// blocks. Anything above zero means the block didn't hold.
	Leaked int64 `json:"leaked"`
}

// BanRecorder fills in ban_forensics for bans dnscount ingest-bans records.
type BanRecorder struct {
	St     *store.Store
	Limits map[string]f2b.Limit
	Log    *log.Logger
	Now    func() time.Time
	// Settle is how long after a ban (or unban) to wait before recording,
	// so the access log and firewall lines around it are in.
	Settle time.Duration
}

const (
	banSamples     = 20 // as many as a trip's ring buffer
	duringSamples  = 10
	backfillAfter  = 10 * time.Minute
	foundSlackLow  = time.Second     // a Found time is whole seconds,
	foundSlackHigh = 2 * time.Second // the request it matched isn't
	batch          = 200
)

// Rule is the host firewall's log prefix for a jail's bans: the guard's
// ban action truncates f2b-<jail> to 26 characters.
func Rule(jail string) string {
	r := "f2b-" + jail
	if len(r) > 26 {
		r = r[:26]
	}
	return r
}

// Run records every Settle (at least every 15s) until ctx is done.
func (r *BanRecorder) Run(ctx context.Context) {
	tick := time.NewTicker(max(r.Settle, 15*time.Second))
	defer tick.Stop()
	for {
		if err := r.Step(); err != nil {
			r.Log.Printf("ban forensics: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Step records what's ready: details for bans at least Settle old, and
// what happened during bans that ended at least Settle ago. It returns once
// a batch of each is done.
func (r *BanRecorder) Step() error {
	now := r.Now()
	pending, err := r.St.BansNeedingForensics(now.Add(-r.Settle), batch)
	if err != nil {
		return err
	}
	for _, p := range pending {
		d := r.detail(p, now)
		blob, err := json.Marshal(d)
		if err != nil {
			return err
		}
		if err := r.St.SetBanDetail(p.ID, blob, now, d.Backfilled); err != nil {
			return err
		}
	}
	ended, err := r.St.BansNeedingDuring(batch)
	if err != nil {
		return err
	}
	for _, b := range ended {
		if now.Sub(b.UnbannedAt) < r.Settle {
			continue
		}
		t, err := r.St.BlockedTrafficFor(b.IP, Rule(b.Jail), b.BannedAt, b.UnbannedAt.Add(time.Second), duringSamples)
		if err != nil {
			return err
		}
		leaked, err := r.St.LeakedHits(b)
		if err != nil {
			return err
		}
		blob, err := json.Marshal(BanDuring{Until: b.UnbannedAt, BlockedTraffic: t, Leaked: leaked})
		if err != nil {
			return err
		}
		if err := r.St.SetBanDuring(b.ID, blob); err != nil {
			return err
		}
	}
	return nil
}

// Drain steps until nothing ready is left, for a one-off import.
func (r *BanRecorder) Drain() error {
	for {
		before, err := r.St.BansNeedingForensics(r.Now().Add(-r.Settle), 1)
		if err != nil || len(before) == 0 {
			if err == nil {
				return r.Step() // the durings
			}
			return err
		}
		if err := r.Step(); err != nil {
			return err
		}
	}
}

func (r *BanRecorder) limit(jail string) f2b.Limit {
	if l, ok := r.Limits[jail]; ok {
		return l
	}
	return f2b.DefaultLimit
}

func (r *BanRecorder) detail(p store.PendingBan, now time.Time) BanDetail {
	lim := r.limit(p.Jail)
	d := BanDetail{Event: p.Event, Jail: p.Jail, MaxRetry: lim.MaxRetry, FindTime: int64(lim.FindTime / time.Second),
		Found: p.Found, Backfilled: now.Sub(p.TS) > backfillAfter, Notes: map[string]string{}}
	if p.RestoredOf != 0 {
		d.RestoredOf = p.RestoredOf
		d.Notes = nil
		return d
	}
	note := func(k string, err error) {
		if err != nil {
			d.Notes[k] = err.Error()
		}
	}
	if len(p.Found) > 0 {
		d.Trigger = &BanTrigger{}
		lo, hi := slices.MinFunc(p.Found, time.Time.Compare), slices.MaxFunc(p.Found, time.Time.Compare)
		from, to := lo.Add(-foundSlackLow), hi.Add(foundSlackHigh)
		near := func(t time.Time) bool {
			for _, f := range p.Found {
				if !t.Before(f.Add(-foundSlackLow)) && t.Before(f.Add(foundSlackHigh)) {
					return true
				}
			}
			return false
		}
		hits, err := r.St.Hits(store.HitFilter{IP: p.IP, Since: from, Until: to, Limit: 200})
		note("trigger_hits", err)
		for _, h := range slices.Backward(hits) {
			if near(h.TS) {
				d.Trigger.Hits = append(d.Trigger.Hits, h)
			}
		}
		logins, err := r.St.AuthFailuresBetween(p.IP, from, to, 200)
		note("trigger_logins", err)
		for _, a := range slices.Backward(logins) {
			if near(a.TS) {
				d.Trigger.Logins = append(d.Trigger.Logins, a)
			}
		}
	} else {
		d.Notes["trigger"] = "no matched-line times: fail2ban's journal no longer had them, or it was a restore"
	}
	// Up to the ban, and the request that caused it if it was logged in
	// the same second.
	end := p.TS.Add(time.Second)
	hits, err := r.St.Hits(store.HitFilter{IP: p.IP, Until: end, Limit: banSamples})
	note("samples", err)
	slices.Reverse(hits)
	d.Samples = hits
	if d.Samples == nil {
		d.Samples = []hit.Hit{}
	}
	window := lim.FindTime
	if window <= 0 {
		window = f2b.DefaultLimit.FindTime
	}
	times, err := r.St.HitTimes(p.IP, end.Add(-window), end)
	note("rate_curve", err)
	d.RateCurve = Curve(times, end.Add(-window), end, curveBuckets)
	if h, err := r.St.IPHistoryAt(p.IP, p.TS); err == nil {
		d.History = &h
	} else {
		note("history", err)
	}
	if len(d.Notes) == 0 {
		d.Notes = nil
	}
	return d
}

const curveBuckets = 10

// Curve counts times into n equal buckets over [from, to).
func Curve(times []time.Time, from, to time.Time, n int) []int {
	out := make([]int, n)
	span := to.Sub(from)
	if span <= 0 {
		return out
	}
	for _, t := range times {
		if t.Before(from) || !t.Before(to) {
			continue
		}
		out[int(int64(t.Sub(from))*int64(n)/int64(span))]++
	}
	return out
}
