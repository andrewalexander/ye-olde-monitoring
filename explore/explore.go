// Package explore is `dnscount explore`: a separate, low-priority process
// that reads the live database read-only and serves the LAN table explorer.
// It keeps its own explore.db with the indicator index and feed matches, so
// nothing it does can hold up ingest.
package explore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"dnscount/enrich"
	"dnscount/store"
)

// Config for an Explorer.
type Config struct {
	DB       string // the live database, opened read-only
	EnrichDB string // explore.db, the explorer's own
	FeedsDir string
	Feeds    []enrich.Feed

	QueryTimeout time.Duration // per API request
	MaxConns     int
	MatchEvery   time.Duration // index and match new indicators
	FeedPoll     time.Duration // look for changed feed files
	SampleEvery  time.Duration
	Window       time.Duration // how far back a list change re-checks
	// ForceReconcile reconciles every list on load, even unchanged ones.
	ForceReconcile bool

	// AdminURL is the live admin listener, for breaker stats. Empty skips them.
	AdminURL string

	Sampler *Sampler // ProcRoot, CgroupRoot, Units; DB and Newest are filled in
	Now     func() time.Time
	Log     *log.Logger
}

// Explorer owns the two database handles and the loaded lists.
type Explorer struct {
	cfg Config
	ro  *store.Store // live db, read-only, explore.db attached
	enr *store.Store // explore.db, read-write

	mu     sync.RWMutex
	lists  store.Lists
	loaded map[string]loadedFeed // by feed name

	statusMu sync.Mutex
	status   loopStatus

	checkMu   sync.Mutex
	checkAt   time.Time
	checkLast []string
	checkErr  error
}

type loadedFeed struct {
	mod     time.Time
	size    int64
	version string
	entries int
	err     string
}

type loopStatus struct {
	LastIndex     time.Time `json:"last_index,omitzero"`
	LastIndexRows int       `json:"last_index_rows"`
	LastMatch     time.Time `json:"last_match,omitzero"`
	LastMatched   int       `json:"last_matched"`
	LastError     string    `json:"last_error,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitzero"`
}

// Open opens both databases. explore.db is created if needed.
func Open(cfg Config) (*Explorer, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = log.Default()
	}
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 10 * time.Second
	}
	if cfg.MatchEvery == 0 {
		cfg.MatchEvery = 10 * time.Minute
	}
	if cfg.FeedPoll == 0 {
		cfg.FeedPoll = time.Minute
	}
	if cfg.SampleEvery == 0 {
		cfg.SampleEvery = 15 * time.Second
	}
	if cfg.Window == 0 {
		cfg.Window = 90 * 24 * time.Hour
	}
	if cfg.Sampler == nil {
		cfg.Sampler = &Sampler{ProcRoot: "/proc", CgroupRoot: "/sys/fs/cgroup/system.slice"}
	}
	if _, err := os.Stat(cfg.DB); err != nil {
		return nil, fmt.Errorf("live database: %w", err)
	}
	enr, err := store.OpenEnrich(cfg.EnrichDB)
	if err != nil {
		return nil, err
	}
	ro, err := store.OpenReadOnly(cfg.DB, cfg.EnrichDB, cfg.MaxConns)
	if err != nil {
		enr.Close()
		return nil, err
	}
	x := &Explorer{cfg: cfg, ro: ro, enr: enr, loaded: map[string]loadedFeed{}}
	cfg.Sampler.DB = cfg.DB
	cfg.Sampler.Newest = func() (time.Time, time.Time, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return x.ro.WithContext(ctx).Newest()
	}
	return x, nil
}

func (x *Explorer) Close() error {
	return errors.Join(x.ro.Close(), x.enr.Close())
}

// Lists is a snapshot of the loaded lists.
func (x *Explorer) Lists() store.Lists {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return store.Lists{Lists: append([]*enrich.List(nil), x.lists.Lists...), ASN: x.lists.ASN}
}

// ReloadFeeds loads every feed file that changed on disk. A list whose
// contents differ from the version last reconciled is reconciled: every
// indicator seen inside the window is re-checked against it.
func (x *Explorer) ReloadFeeds() error {
	var errs []error
	now := x.cfg.Now()
	since := now.Add(-x.cfg.Window)
	for _, f := range x.cfg.Feeds {
		path := f.File(x.cfg.FeedsDir)
		fi, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // not downloaded yet
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		x.mu.RLock()
		old, seen := x.loaded[f.Name]
		x.mu.RUnlock()
		if seen && old.mod.Equal(fi.ModTime()) && old.size == fi.Size() {
			continue
		}
		lf := loadedFeed{mod: fi.ModTime(), size: fi.Size()}
		if f.Format == "iptoasn" {
			t, err := enrich.LoadASN(path)
			if err == nil {
				lf.version, lf.entries = t.Version, t.Entries
				var prev string
				if prev, err = x.enr.FeedVersion("asn:iptoasn"); err == nil {
					x.mu.Lock()
					x.lists.ASN = t
					x.mu.Unlock()
					if prev != t.Version || x.cfg.ForceReconcile {
						var n int
						n, err = x.enr.ReconcileASN(t, since, now)
						x.cfg.Log.Printf("iptoasn %s: %d entries, %d owners changed", t.Version, t.Entries, n)
					}
				}
			}
			x.setLoaded(f.Name, lf, err)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
			}
			continue
		}
		l, err := enrich.LoadList(f, path)
		if err == nil {
			lf.version, lf.entries = l.Version, l.Entries
			x.mu.Lock()
			replaced := false
			for i, have := range x.lists.Lists {
				if have.Name == f.Name {
					x.lists.Lists[i], replaced = l, true
				}
			}
			if !replaced {
				x.lists.Lists = append(x.lists.Lists, l)
			}
			x.mu.Unlock()
			var prev string
			if prev, err = x.enr.FeedVersion(l.Provider()); err == nil && (prev != l.Version || x.cfg.ForceReconcile) {
				var st store.ReconcileStats
				st, err = x.enr.Reconcile(l, since, now)
				x.cfg.Log.Printf("feed %s %s: %d entries; checked %d, %d listed (%d new), %d removed",
					f.Name, l.Version, l.Entries, st.Checked, st.Listed, st.Added, st.Removed)
			}
		}
		x.setLoaded(f.Name, lf, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (x *Explorer) setLoaded(name string, lf loadedFeed, err error) {
	if err != nil {
		lf.err = err.Error()
	}
	x.mu.Lock()
	x.loaded[name] = lf
	x.mu.Unlock()
}

// IndexAndMatch reads new rows from the live database into the index, then
// matches every indicator not yet checked.
func (x *Explorer) IndexAndMatch(ctx context.Context) error {
	n, err := store.IndexNew(x.ro.WithContext(ctx), x.enr.WithContext(ctx), 0)
	now := x.cfg.Now()
	x.statusMu.Lock()
	x.status.LastIndex, x.status.LastIndexRows = now, n
	x.statusMu.Unlock()
	if err != nil {
		return err
	}
	m, err := x.enr.WithContext(ctx).MatchNew(x.Lists(), now)
	x.statusMu.Lock()
	x.status.LastMatch, x.status.LastMatched = now, m
	x.statusMu.Unlock()
	return err
}

// Tick is one pass of everything the loops do.
func (x *Explorer) Tick(ctx context.Context) error {
	return errors.Join(x.ReloadFeeds(), x.IndexAndMatch(ctx))
}

func (x *Explorer) noteErr(what string, err error) {
	if err == nil {
		return
	}
	x.cfg.Log.Printf("%s: %v", what, err)
	x.statusMu.Lock()
	x.status.LastError, x.status.LastErrorAt = what+": "+err.Error(), x.cfg.Now()
	x.statusMu.Unlock()
}

// Run serves addr and runs the loops until ctx ends.
func (x *Explorer) Run(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: x.Handler(), ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout: x.cfg.QueryTimeout + 20*time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	x.cfg.Sampler.Take(x.cfg.Now())
	x.noteErr("feeds", x.ReloadFeeds())
	x.noteErr("index", x.IndexAndMatch(ctx))

	match := time.NewTicker(x.cfg.MatchEvery)
	feeds := time.NewTicker(x.cfg.FeedPoll)
	sample := time.NewTicker(x.cfg.SampleEvery)
	defer match.Stop()
	defer feeds.Stop()
	defer sample.Stop()
	for {
		select {
		case <-ctx.Done():
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shut)
		case err := <-errc:
			return err
		case <-sample.C:
			x.cfg.Sampler.Take(x.cfg.Now())
		case <-feeds.C:
			x.noteErr("feeds", x.ReloadFeeds())
		case <-match.C:
			x.noteErr("index", x.IndexAndMatch(ctx))
		}
	}
}

// checks runs the live database's sanity checks at most every 10 minutes:
// they scan whole tables.
func (x *Explorer) checks(ctx context.Context) ([]string, time.Time, error) {
	x.checkMu.Lock()
	defer x.checkMu.Unlock()
	now := x.cfg.Now()
	if x.checkAt.IsZero() || now.Sub(x.checkAt) > 10*time.Minute {
		x.checkLast, x.checkErr = x.ro.WithContext(ctx).Check(now)
		x.checkAt = now
	}
	return x.checkLast, x.checkAt, x.checkErr
}
