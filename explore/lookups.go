package explore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"dnscount/enrich"
	"dnscount/store"
)

// ProviderLimits caps one queried provider. Zero means no cap.
type ProviderLimits struct {
	Daily   int    `json:"daily"`   // units in any 24 hours
	Monthly int    `json:"monthly"` // units this calendar month (UTC)
	TTL     string `json:"ttl"`     // re-ask after this long, e.g. "168h"
	Base    string `json:"base"`    // API base URL (tests, VM tests)
}

// LookupsConfig is the lookups config file (services.dnscount.lookups writes
// it; DNSCOUNT_LOOKUPS_CONFIG points at it).
type LookupsConfig struct {
	Never     []string                  `json:"never"`     // our own domains, never looked up
	Automatic []string                  `json:"automatic"` // providers the timer runs
	Providers map[string]ProviderLimits `json:"providers"`
}

// DefaultLimits are used for providers the config doesn't mention.
var DefaultLimits = map[string]ProviderLimits{
	// No published limit; be polite.
	"internetdb": {Daily: 500, TTL: "168h"},
	// 1,000 checks a day on a free account; leave room for anything manual.
	"abuseipdb": {Daily: 800, TTL: "168h"},
	// 100 credits a month plus 5 free actions a day on a free account.
	"censys": {Daily: 5, Monthly: 100, TTL: "720h"},
}

// LoadLookupsConfig reads path (empty: defaults only).
func LoadLookupsConfig(path string) (LookupsConfig, error) {
	c := LookupsConfig{Automatic: []string{"internetdb", "abuseipdb"}, Providers: map[string]ProviderLimits{}}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	}
	for name, d := range DefaultLimits {
		l, ok := c.Providers[name]
		if !ok {
			c.Providers[name] = d
			continue
		}
		if l.TTL == "" {
			l.TTL = d.TTL
		}
		c.Providers[name] = l
	}
	return c, nil
}

// LoadKeys reads KEY=value lines (comments and blank lines ignored). Values
// are never printed. A missing file is no keys: providers that need one are
// skipped, and keyless ones still run.
func LoadKeys(path string) (map[string]string, error) {
	keys := map[string]string{}
	if path == "" {
		return keys, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return keys, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		keys[strings.TrimSpace(strings.TrimPrefix(k, "export "))] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return keys, nil
}

// Key names in the key file (or the environment).
const (
	KeyAbuseIPDB = "ABUSE_IPDB_KEY"
	KeyCensys    = "CENSYS_TOKEN"
)

// NewProvider builds a queried provider by name. A provider that needs a
// key it doesn't have returns an error saying which.
func NewProvider(name string, l ProviderLimits, keys map[string]string) (enrich.Queried, error) {
	key := func(k string) string {
		if v := keys[k]; v != "" {
			return v
		}
		return os.Getenv(k)
	}
	switch name {
	case "internetdb":
		return enrich.NewInternetDB(l.Base), nil
	case "abuseipdb":
		k := key(KeyAbuseIPDB)
		if k == "" {
			return nil, fmt.Errorf("abuseipdb needs %s in the key file", KeyAbuseIPDB)
		}
		return enrich.NewAbuseIPDB(l.Base, k), nil
	case "censys":
		k := key(KeyCensys)
		if k == "" {
			return nil, fmt.Errorf("censys needs %s in the key file", KeyCensys)
		}
		return enrich.NewCensys(l.Base, k), nil
	}
	return nil, fmt.Errorf("unknown provider %q (internetdb, abuseipdb, censys)", name)
}

// ProviderRun is one provider in a lookup run, with its limits.
type ProviderRun struct {
	P      enrich.Queried
	Limits ProviderLimits
}

// LookupRun asks queried providers about the indicators worth asking
// about, through the privacy gate, skipping what's cached, within budget.
type LookupRun struct {
	RO, Enr   *store.Store // the live database (read-only, explore.db attached) and explore.db
	Providers []ProviderRun
	Never     []string      // our own domains
	Since     time.Duration // how far back to pick candidates
	Extra     []string      // indicators asked for by hand (still gated)
	Limit     int           // at most this many indicators per provider (0: no limit)
	DryRun    bool
	Now       func() time.Time
	Out       io.Writer
}

// ProviderResult is what one provider did in a run.
type ProviderResult struct {
	Provider string
	Asked    int
	Found    int
	Units    int
	Stopped  string // why it stopped early, if it did
}

func (r *LookupRun) printf(format string, args ...any) {
	if r.Out != nil {
		fmt.Fprintf(r.Out, format, args...)
	}
}

// Run does one pass. It returns what each provider did; an error is only
// for failures of the run itself (the store, the gate), not for a provider
// refusing, which stops that provider and is reported in its result.
func (r *LookupRun) Run(ctx context.Context) ([]ProviderResult, error) {
	if r.Now == nil {
		r.Now = time.Now
	}
	now := r.Now()
	lan, err := r.RO.LANAddresses()
	if err != nil {
		return nil, fmt.Errorf("loading LAN addresses for the privacy gate (nothing was sent): %w", err)
	}
	gate := &enrich.Gate{LAN: lan, Own: r.Never}
	if r.Since == 0 {
		r.Since = 7 * 24 * time.Hour
	}
	cands, err := r.RO.LookupCandidates(now.Add(-r.Since), now)
	if err != nil {
		return nil, err
	}
	// Indicators asked for by hand go first.
	var extra []store.Candidate
	for _, e := range r.Extra {
		kind := "domain"
		if a, err := netip.ParseAddr(e); err == nil {
			e, kind = a.Unmap().String(), "ip"
		}
		extra = append(extra, store.Candidate{Indicator: e, Kind: kind, Reason: "asked for"})
	}
	cands = append(extra, cands...)

	var allowed []store.Candidate
	refused := map[string]string{}
	for _, c := range cands {
		if ok, why := gate.Allow(c.Indicator); ok {
			allowed = append(allowed, c)
		} else if _, dup := refused[c.Indicator]; !dup {
			refused[c.Indicator] = why
		}
	}
	if r.DryRun && len(refused) > 0 {
		r.printf("never sent (privacy gate):\n")
		for ind, why := range refused {
			r.printf("  %-40s %s\n", ind, why)
		}
	}

	var results []ProviderResult
	for _, pr := range r.Providers {
		res, err := r.runProvider(ctx, pr, allowed, now)
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

func (r *LookupRun) runProvider(ctx context.Context, pr ProviderRun, cands []store.Candidate, now time.Time) (ProviderResult, error) {
	p := pr.P
	res := ProviderResult{Provider: p.Name()}
	ttl, err := time.ParseDuration(pr.Limits.TTL)
	if err != nil || ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	var mine []store.Candidate
	kinds := map[string]string{}
	var inds []string
	for _, c := range cands {
		if p.Handles(c.Kind) && kinds[c.Indicator] == "" {
			mine = append(mine, c)
			kinds[c.Indicator] = c.Kind
			inds = append(inds, c.Indicator)
		}
	}
	fresh, err := r.Enr.FreshLookups(p.Name(), inds, ttl, now)
	if err != nil {
		return res, err
	}
	var todo []store.Candidate
	cached := 0
	for _, c := range mine {
		if fresh[c.Indicator] {
			cached++
		} else {
			todo = append(todo, c)
		}
	}

	// The budget: what's left of each cap, counted from the request log.
	left := -1
	day, err := r.Enr.LookupUnits(p.Name(), now.Add(-24*time.Hour))
	if err != nil {
		return res, err
	}
	month, err := r.Enr.LookupUnits(p.Name(), time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		return res, err
	}
	if c := pr.Limits.Daily; c > 0 {
		left = max(0, c-day)
	}
	if c := pr.Limits.Monthly; c > 0 {
		if l := max(0, c-month); left < 0 || l < left {
			left = l
		}
	}
	over := 0
	if left >= 0 && len(todo) > left {
		over, todo = len(todo)-left, todo[:left]
	}
	if r.Limit > 0 && len(todo) > r.Limit {
		todo = todo[:r.Limit]
	}

	if r.DryRun {
		r.printf("\n%s: would ask about %d (up to %d units); %d cached; used %d in 24h, %d this month",
			p.Name(), len(todo), len(todo), cached, day, month)
		if over > 0 {
			r.printf("; %d more over budget", over)
		}
		r.printf("\n")
		for _, c := range todo {
			r.printf("  %-40s %s\n", c.Indicator, c.Reason)
		}
		res.Asked = len(todo)
		return res, nil
	}

	batch := max(1, p.BatchSize())
	for start := 0; start < len(todo); start += batch {
		var chunk []string
		for _, c := range todo[start:min(start+batch, len(todo))] {
			chunk = append(chunk, c.Indicator)
		}
		answers, units, err := p.Lookup(ctx, chunk)
		ts := r.Now()
		res.Asked += len(chunk)
		res.Units += units
		status, msg := "ok", ""
		if err != nil {
			status, msg = "error", err.Error()
			if IsCtx(err) {
				status = "cancelled"
			}
		}
		if lerr := r.Enr.LogLookup(p.Name(), chunk, status, units, msg, ts); lerr != nil {
			return res, lerr
		}
		if len(answers) > 0 {
			if serr := r.Enr.SaveLookups(p.Name(), kinds, answers, ts); serr != nil {
				return res, serr
			}
			for _, a := range answers {
				if a.Found {
					res.Found++
				}
			}
		}
		if err != nil {
			// Refusals, network trouble, cancellation: stop this provider
			// for the run rather than keep knocking.
			res.Stopped = err.Error()
			break
		}
	}
	r.printf("%s: asked about %d, found %d, used %d units; %d cached", p.Name(), res.Asked, res.Found, res.Units, cached)
	if over > 0 {
		r.printf("; %d over budget, left for later", over)
	}
	if res.Stopped != "" {
		r.printf("; stopped: %s", res.Stopped)
	}
	r.printf("\n")
	return res, nil
}

// IsCtx says whether err is a cancelled or timed-out context.
func IsCtx(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
