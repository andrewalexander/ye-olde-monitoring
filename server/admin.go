package server

import (
	"database/sql"
	_ "embed"
	"errors"
	"net/http"
	"strconv"
	"time"

	"dnscount/breaker"
	"dnscount/store"
)

// Admin is the research API. It has no auth: bind it to localhost only and
// reach it over an SSH tunnel.
func (s *Server) Admin(extraHealth func() map[string]any) http.Handler {
	mux := http.NewServeMux()
	st := s.cfg.Store
	mux.HandleFunc("GET /api", serveAPIDoc)
	mux.HandleFunc("GET /api/{$}", serveAPIDoc)
	mux.HandleFunc("GET /api/hits", s.api(func(r *http.Request, p *params) (any, error) {
		return st.Hits(store.HitFilter{Site: p.str("site"), IP: p.str("ip"), Status: p.str("status"), Since: p.since(), Limit: p.int("limit")})
	}))
	mux.HandleFunc("GET /api/top", s.api(func(r *http.Request, p *params) (any, error) {
		q := p.group("ip")
		q.Site, q.IP, q.Status = p.str("site"), p.str("ip"), p.str("status")
		return st.TopHits(q)
	}))
	mux.HandleFunc("GET /api/dns", s.api(func(r *http.Request, p *params) (any, error) {
		if d := p.str("domain"); d != "" {
			lookups, err := st.DNSByDomain(d, p.since())
			if err != nil {
				return nil, err
			}
			conns, err := st.ConnsForDomain(d, p.since())
			return map[string]any{"lookups": lookups, "connections": conns}, err
		}
		if c := p.str("client"); c != "" {
			lookups, err := st.DNSByClient(c, p.since(), p.int("limit"))
			if err != nil {
				return nil, err
			}
			conns, err := st.ConnsForClient(c, p.since())
			return map[string]any{"lookups": lookups, "connections": conns}, err
		}
		return nil, errBadParam("need domain= or client=")
	}))
	mux.HandleFunc("GET /api/dns/top", s.api(func(r *http.Request, p *params) (any, error) {
		return st.DNSTop(p.group("domain"))
	}))
	mux.HandleFunc("GET /api/alerts", s.api(func(r *http.Request, p *params) (any, error) {
		f := store.AlertFilter{Since: p.since(), IP: p.str("ip"), Action: p.str("action"), Limit: p.int("limit")}
		if by := p.str("by"); by != "" {
			return st.TopAlerts(by, f)
		}
		return st.Alerts(f)
	}))
	mux.HandleFunc("GET /api/bans", s.api(func(r *http.Request, p *params) (any, error) {
		return st.Bans(store.BanFilter{Since: p.since(), IP: p.str("ip"), Jail: p.str("jail"), Limit: p.int("limit")}, s.cfg.Now())
	}))
	mux.HandleFunc("GET /api/trips", s.api(func(r *http.Request, p *params) (any, error) {
		return st.Trips(store.TripFilter{Since: p.since(), Key: p.str("ip"), Breaker: p.str("breaker"), Limit: p.int("limit")})
	}))
	mux.HandleFunc("GET /api/trips/{id}", s.api(func(r *http.Request, p *params) (any, error) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			return nil, errBadParam("id must be a number")
		}
		t, err := st.Trip(id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errNotFound
		}
		return t, err
	}))
	mux.HandleFunc("GET /api/health", s.api(func(r *http.Request, p *params) (any, error) {
		h := map[string]any{"breakers": []breaker.Stats{s.Counter.Stats(), s.Ingest.Stats()}}
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

// apiDoc is the plain-text endpoint reference served at GET /api.
//
//go:embed api.txt
var apiDoc string

func serveAPIDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(apiDoc))
}

type errBadParam string

func (e errBadParam) Error() string { return string(e) }

var errNotFound = errors.New("not found")

type params struct {
	r   *http.Request
	s   *Server
	err error
}

func (p *params) str(k string) string { return p.r.URL.Query().Get(k) }

func (p *params) strOr(k, def string) string {
	if v := p.str(k); v != "" {
		return v
	}
	return def
}

func (p *params) int(k string) int { return p.intOr(k, 0) }

func (p *params) intOr(k string, def int) int {
	v := p.str(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil && p.err == nil {
		p.err = errBadParam(k + " must be a number")
	}
	return n
}

func (p *params) since() time.Time {
	t, err := store.ParseSince(p.str("since"), p.s.cfg.Now())
	if err != nil && p.err == nil {
		p.err = errBadParam(err.Error())
	}
	return t
}

// group reads the parameters shared by the grouped reports. order=new needs a
// window to mean anything, so it defaults to the last 24 hours.
func (p *params) group(by string) store.GroupQuery {
	rank := store.Rank(p.strOr("order", string(store.RankTop)))
	q := store.GroupQuery{By: p.strOr("by", by), Limit: p.intOr("limit", 25), Rank: rank}
	if rank == store.RankNew && p.str("since") == "" {
		q.Since = p.s.cfg.Now().Add(-24 * time.Hour)
	} else {
		q.Since = p.since()
	}
	return q
}

func (s *Server) api(f func(*http.Request, *params) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := &params{r: r, s: s}
		v, err := f(r, p)
		if err == nil {
			err = p.err
		}
		var bp errBadParam
		var bq store.BadQueryError
		switch {
		case errors.As(err, &bp), errors.As(err, &bq):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, errNotFound):
			http.Error(w, "not found", http.StatusNotFound)
		case err != nil:
			s.cfg.Log.Printf("admin %s: %v", r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			writeJSON(w, v)
		}
	}
}
