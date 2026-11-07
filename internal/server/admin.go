package server

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/guard"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// Admin is the research API. It has no auth: bind it to localhost only and
// reach it over an SSH tunnel.
func (s *Server) Admin(extraHealth func() map[string]any) http.Handler {
	mux := http.NewServeMux()
	rc := RouteConfig{Store: s.cfg.Store, Now: s.cfg.Now, Log: s.cfg.Log}
	mux.HandleFunc("GET /api", serveAPIDoc)
	mux.HandleFunc("GET /api/{$}", serveAPIDoc)
	for pattern, h := range ReadRoutes(rc) {
		mux.HandleFunc(pattern, h)
	}
	mux.HandleFunc("GET /api/health", rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
		h := map[string]any{"breakers": []guard.Stats{s.Counter.Stats(), s.Ingest.Stats()}}
		if extraHealth != nil {
			for k, v := range extraHealth() {
				h[k] = v
			}
		}
		problems, err := st.Check(s.cfg.Now())
		h["data_problems"] = problems
		return h, err
	}))
	return mux
}

// RouteConfig is what the read-only API handlers need. The admin listener
// and the explorer each build one over their own store.
type RouteConfig struct {
	Store *store.Store
	Now   func() time.Time
	Log   *log.Logger
	// Timeout bounds each request's queries; 0 means none.
	Timeout time.Duration
	// Observe, if set, is told how long each request took.
	Observe func(path string, took time.Duration, status int, err error)
}

// HandlerFunc answers one API request with a value to encode as JSON. st is
// already bound to the request's context.
type HandlerFunc func(st *store.Store, r *http.Request, p *Params) (any, error)

// ReadRoutes is the read-only research API, by ServeMux pattern. Callers may
// replace entries before registering them.
func ReadRoutes(rc RouteConfig) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /api/hits": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			return st.Hits(store.HitFilter{Site: p.Str("site"), IP: p.Str("ip"), Status: p.Str("status"), Since: p.Since(), Limit: p.Int("limit")})
		}),
		"GET /api/top": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			q := p.Group("ip")
			q.Site, q.IP, q.Status = p.Str("site"), p.Str("ip"), p.Str("status")
			return st.TopHits(q)
		}),
		"GET /api/dns": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			if d := p.Str("domain"); d != "" {
				lookups, err := st.DNSByDomain(d, p.Since())
				if err != nil {
					return nil, err
				}
				conns, err := st.ConnsForDomain(d, p.Since())
				return map[string]any{"lookups": lookups, "connections": conns}, err
			}
			if c := p.Str("client"); c != "" {
				lookups, err := st.DNSByClient(c, p.Since(), p.Int("limit"))
				if err != nil {
					return nil, err
				}
				conns, err := st.ConnsForClient(c, p.Since())
				return map[string]any{"lookups": lookups, "connections": conns}, err
			}
			return nil, ErrBadParam("need domain= or client=")
		}),
		"GET /api/dns/top": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			return st.DNSTop(p.Group("domain"))
		}),
		"GET /api/alerts": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			f := p.AlertFilter()
			if by := p.Str("by"); by != "" {
				return st.TopAlerts(by, f)
			}
			return st.Alerts(f)
		}),
		"GET /api/bans": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			return st.Bans(p.BanFilter(), rc.Now())
		}),
		"GET /api/trips": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			return st.Trips(store.TripFilter{Since: p.Since(), Key: p.Str("ip"), Breaker: p.Str("breaker"), Limit: p.Int("limit")})
		}),
		"GET /api/trips/{id}": rc.Handle(func(st *store.Store, r *http.Request, p *Params) (any, error) {
			id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
			if err != nil {
				return nil, ErrBadParam("id must be a number")
			}
			t, err := st.Trip(id)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return t, err
		}),
	}
}

// apiDoc is the plain-text endpoint reference served at GET /api.
//
//go:embed api.txt
var apiDoc string

func serveAPIDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(apiDoc))
}

// ErrBadParam is a 400.
type ErrBadParam string

func (e ErrBadParam) Error() string { return string(e) }

// ErrNotFound is a 404.
var ErrNotFound = errors.New("not found")

// Params reads a request's query parameters, remembering the first bad one.
type Params struct {
	r   *http.Request
	now func() time.Time
	err error
}

func (p *Params) Str(k string) string { return p.r.URL.Query().Get(k) }

func (p *Params) StrOr(k, def string) string {
	if v := p.Str(k); v != "" {
		return v
	}
	return def
}

func (p *Params) Int(k string) int { return p.IntOr(k, 0) }

func (p *Params) IntOr(k string, def int) int {
	v := p.Str(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil && p.err == nil {
		p.err = ErrBadParam(k + " must be a number")
	}
	return n
}

// Bool reads 1/true/yes as true.
func (p *Params) Bool(k string) bool {
	switch p.Str(k) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func (p *Params) Since() time.Time { return p.SinceOr("") }

// SinceOr reads since=, defaulting to def (a since= value) when it's absent.
func (p *Params) SinceOr(def string) time.Time {
	t, err := store.ParseSince(p.StrOr("since", def), p.now())
	if err != nil && p.err == nil {
		p.err = ErrBadParam(err.Error())
	}
	return t
}

// Group reads the parameters shared by the grouped reports. order=new needs a
// window to mean anything, so it defaults to the last 24 hours.
func (p *Params) Group(by string) store.GroupQuery {
	rank := store.Rank(p.StrOr("order", string(store.RankTop)))
	q := store.GroupQuery{By: p.StrOr("by", by), Limit: p.IntOr("limit", 25), Rank: rank}
	if rank == store.RankNew && p.Str("since") == "" {
		q.Since = p.now().Add(-24 * time.Hour)
	} else {
		q.Since = p.Since()
	}
	return q
}

func (p *Params) AlertFilter() store.AlertFilter {
	return store.AlertFilter{Since: p.Since(), IP: p.Str("ip"), Action: p.Str("action"), Limit: p.Int("limit")}
}

func (p *Params) BanFilter() store.BanFilter {
	return store.BanFilter{Since: p.Since(), IP: p.Str("ip"), Jail: p.Str("jail"), Limit: p.Int("limit")}
}

// Handle turns f into an http.HandlerFunc: parameters, a per-request
// deadline, errors to status codes, and the value to JSON.
func (rc RouteConfig) Handle(f HandlerFunc) http.HandlerFunc {
	if rc.Now == nil {
		rc.Now = time.Now
	}
	if rc.Log == nil {
		rc.Log = log.Default()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		if rc.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, rc.Timeout)
			defer cancel()
		}
		p := &Params{r: r, now: rc.Now}
		v, err := f(rc.Store.WithContext(ctx), r, p)
		if err == nil {
			err = p.err
		}
		var bp ErrBadParam
		var bq store.BadQueryError
		status, msg := http.StatusOK, ""
		switch {
		case errors.As(err, &bp), errors.As(err, &bq):
			status, msg = http.StatusBadRequest, err.Error()
		case errors.Is(err, ErrNotFound):
			status, msg = http.StatusNotFound, "not found"
		case err != nil && ctx.Err() != nil:
			status, msg = http.StatusServiceUnavailable, "query took longer than "+rc.Timeout.String()+"; narrow since= or limit="
		case err != nil:
			rc.Log.Printf("api %s: %v", r.URL.Path, err)
			status, msg = http.StatusInternalServerError, err.Error()
		}
		if rc.Observe != nil {
			rc.Observe(r.URL.Path, time.Since(start), status, err)
		}
		if status != http.StatusOK {
			http.Error(w, msg, status)
			return
		}
		WriteJSON(w, v)
	}
}
