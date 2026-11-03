package explore

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"dnscount/enrich"
	"dnscount/server"
	"dnscount/store"
)

//go:embed ui
var uiFiles embed.FS

// Thresholds the Health view colours by; served so the UI and docs agree.
var Thresholds = map[string]float64{
	"wal_bytes":    64 << 20,
	"psi_pct":      10,
	"dns_age_s":    600,
	"query_p95_ms": 2000,
}

// Handler is the explorer's UI and API.
func (x *Explorer) Handler() http.Handler {
	rc := server.RouteConfig{Store: x.ro, Now: x.cfg.Now, Log: x.cfg.Log, Timeout: x.cfg.QueryTimeout,
		Observe: x.cfg.Sampler.Observe}
	routes := server.ReadRoutes(rc)
	h := rc.Handle

	// The shared endpoints, with what's known about each address added.
	routes["GET /api/alerts"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		f := p.AlertFilter()
		if by := p.Str("by"); by != "" {
			return st.TopAlerts(by, f)
		}
		alerts, err := st.Alerts(f)
		if err != nil {
			return nil, err
		}
		intel, err := st.Intel(keys(alerts, func(a store.Alert) string { return a.SrcIP }), false)
		type row struct {
			store.Alert
			*store.Intel
		}
		out := make([]row, len(alerts))
		for i, a := range alerts {
			out[i] = row{a, intel[a.SrcIP]}
		}
		return out, err
	})
	routes["GET /api/bans"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		bans, err := st.Bans(p.BanFilter(), x.cfg.Now())
		if err != nil {
			return nil, err
		}
		intel, err := st.Intel(keys(bans, func(b store.Ban) string { return b.IP }), false)
		type row struct {
			store.Ban
			*store.Intel
		}
		out := make([]row, len(bans))
		for i, b := range bans {
			out[i] = row{b, intel[b.IP]}
		}
		return out, err
	})

	list := func(p *server.Params) store.ListQuery {
		return store.ListQuery{Since: p.SinceOr("7d"), Flagged: p.Bool("flagged"), Order: p.Str("order"), Limit: p.Int("limit")}
	}
	routes["GET /api/ips"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return st.InboundIPs(list(p), x.cfg.Now())
	})
	routes["GET /api/ip/{ip}"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		a, err := netip.ParseAddr(r.PathValue("ip"))
		if err != nil {
			return nil, server.ErrBadParam("not an IP address")
		}
		ip := a.Unmap().String()
		if err := x.enr.WithContext(r.Context()).Rematch(ip, x.Lists(), x.cfg.Now()); err != nil {
			return nil, err
		}
		return st.IPProfile(ip, p.SinceOr("30d"), x.cfg.Now())
	})
	routes["GET /api/device/{ip}"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		a, err := netip.ParseAddr(r.PathValue("ip"))
		if err != nil {
			return nil, server.ErrBadParam("not an IP address")
		}
		ip := a.Unmap().String()
		dev, err := st.Devices([]string{ip}, time.Time{})
		if err != nil {
			return nil, err
		}
		sightings, err := st.DeviceSightings(ip, p.IntOr("limit", 100))
		out := map[string]any{"ip": ip, "sightings": sightings}
		if d, ok := dev[ip]; ok {
			out["device"] = d
		}
		return out, err
	})
	routes["GET /api/domains"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return st.Domains(list(p))
	})
	routes["GET /api/domain/{domain}"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		d := strings.ToLower(strings.TrimSuffix(r.PathValue("domain"), "."))
		if d == "" || strings.ContainsAny(d, " /") {
			return nil, server.ErrBadParam("not a domain")
		}
		if err := x.enr.WithContext(r.Context()).Rematch(d, x.Lists(), x.cfg.Now()); err != nil {
			return nil, err
		}
		return st.DomainProfile(d, p.SinceOr("30d"))
	})
	routes["GET /api/clients"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return st.Clients(p.SinceOr("7d"))
	})
	routes["GET /api/flagged"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		q := store.FlaggedQuery{Since: p.SinceOr("30d"), Limit: p.Int("limit")}
		if v := p.Str("verdict"); v == "all" {
			q.Verdicts = []string{enrich.Malicious, enrich.Suspicious, enrich.Info}
		} else if v != "" {
			q.Verdicts = strings.Split(v, ",")
		}
		return st.Flagged(q)
	})
	routes["GET /api/feeds"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return x.feedStatus(r.Context())
	})
	routes["GET /api/overview"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return x.overview(st)
	})
	routes["GET /api/health"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return x.health(r.Context())
	})
	routes["GET /api/health/series"] = h(func(st *store.Store, r *http.Request, p *server.Params) (any, error) {
		return x.cfg.Sampler.Series(p.SinceOr("6h"), p.IntOr("points", 360)), nil
	})

	mux := http.NewServeMux()
	for pattern, f := range routes {
		mux.HandleFunc(pattern, f)
	}
	mux.HandleFunc("GET /api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(apiDoc))
	})
	ui, _ := fs.Sub(uiFiles, "ui")
	files := http.FileServerFS(ui)
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", files))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, ui, "index.html")
	})
	return secure(mux)
}

// secure adds the headers every response gets. The data shown is largely
// attacker-controlled (paths, user agents), so the UI renders it as text and
// the CSP forbids inline script as a second line.
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

func keys[T any](rows []T, f func(T) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if k := f(r); !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// FeedStatus is one feed as the Health and Overview views show it.
type FeedStatus struct {
	Name       string    `json:"name"`
	About      string    `json:"about,omitempty"`
	Kind       string    `json:"kind"`
	Verdict    string    `json:"verdict,omitempty"`
	Interval   string    `json:"interval"`
	Entries    int       `json:"entries"`
	Version    string    `json:"version,omitempty"`
	LastOK     time.Time `json:"last_ok,omitzero"`
	LastChange time.Time `json:"last_change,omitzero"`
	AgeS       float64   `json:"age_s"` // since the last good fetch; -1 if never
	Stale      bool      `json:"stale"`
	Skipped    string    `json:"skipped,omitempty"`
	Error      string    `json:"error,omitempty"`
	Outdated   int64     `json:"outdated_rows"` // window rows not yet checked against this version
}

func (x *Explorer) feedStatus(ctx context.Context) ([]FeedStatus, error) {
	st, err := enrich.ReadState(x.cfg.FeedsDir)
	if err != nil {
		return nil, err
	}
	now := x.cfg.Now()
	outdated, err := x.enr.WithContext(ctx).OutdatedRows(now.Add(-x.cfg.Window))
	if err != nil {
		return nil, err
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	var out []FeedStatus
	for _, f := range x.cfg.Feeds {
		fs := FeedStatus{Name: f.Name, About: f.About, Kind: f.Kind, Verdict: f.Verdict, Interval: f.Interval.String(), AgeS: -1}
		s := st[f.Name]
		if s != nil {
			fs.LastOK, fs.LastChange, fs.Skipped, fs.Error = s.LastOK, s.LastChange, s.Skipped, s.LastError
			if !s.LastOK.IsZero() {
				fs.AgeS = now.Sub(s.LastOK).Seconds()
			}
		}
		fs.Stale = s == nil || s.Stale(f, now)
		if lf, ok := x.loaded[f.Name]; ok {
			fs.Entries, fs.Version = lf.entries, lf.version
			if lf.err != "" {
				fs.Error = strings.TrimSpace(fs.Error + "; load: " + lf.err)
			}
		}
		fs.Outdated = outdated[f.Provider()]
		out = append(out, fs)
	}
	return out, nil
}

func (x *Explorer) overview(st *store.Store) (map[string]any, error) {
	counts := map[string]map[string]int64{}
	day := store.FormatTime(x.cfg.Now().Add(-24 * time.Hour))
	for _, t := range []struct{ table, ts string }{
		{"hits", "ts"}, {"dns_queries", "ts"}, {"dns_replies", ""}, {"connections", ""},
		{"ids_alerts", "ts"}, {"bans", "ts"}, {"breaker_trips", "tripped_at"},
	} {
		c := map[string]int64{}
		var rows int64
		// Rows are never deleted, so the largest id is the row count without a scan.
		if err := st.DB().QueryRowContext(st.Context(), `SELECT coalesce(max(id), 0) FROM `+t.table).Scan(&rows); err != nil {
			return nil, err
		}
		c["rows"] = rows
		if t.ts != "" {
			var n int64
			if err := st.DB().QueryRowContext(st.Context(), `SELECT count(*) FROM `+t.table+` WHERE `+t.ts+` >= ?`, day).Scan(&n); err != nil {
				return nil, err
			}
			c["last_24h"] = n
		}
		counts[t.table] = c
	}
	var inds, flagged int64
	if err := st.DB().QueryRowContext(st.Context(), `SELECT count(*) FROM enrich.indicators`).Scan(&inds); err != nil {
		return nil, err
	}
	// Flagged as the Flagged view counts it: listed malicious or suspicious,
	// not a LAN device, not a reserved address.
	rows, err := st.DB().QueryContext(st.Context(), `SELECT DISTINCT indicator FROM enrich.enrichment
		WHERE listed = 1 AND verdict IN ('malicious','suspicious')
		AND indicator NOT IN (SELECT ip FROM enrich.lan_clients)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ind string
		if err := rows.Scan(&ind); err != nil {
			return nil, err
		}
		if !enrich.Reserved(ind) {
			flagged++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	x.statusMu.Lock()
	status := x.status
	x.statusMu.Unlock()
	return map[string]any{"tables": counts, "indicators": inds, "flagged": flagged, "loops": status}, nil
}

func (x *Explorer) health(ctx context.Context) (map[string]any, error) {
	out := map[string]any{"thresholds": Thresholds}
	if s, ok := x.cfg.Sampler.Latest(); ok {
		out["now"] = s
	}
	out["slow_queries"] = x.cfg.Sampler.Slow()
	feeds, err := x.feedStatus(ctx)
	if err != nil {
		return nil, err
	}
	out["feeds"] = feeds
	// The checks scan whole tables: give them their own deadline, and cache.
	cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	problems, at, err := x.checks(cctx)
	out["data_problems"], out["checked_at"] = problems, at
	if err != nil {
		out["check_error"] = err.Error()
	}
	x.statusMu.Lock()
	out["loops"] = x.status
	x.statusMu.Unlock()
	if x.cfg.AdminURL != "" {
		out["breakers"], out["admin_error"] = x.breakers(ctx)
	}
	return out, nil
}

// breakers asks the live admin listener for its breaker stats.
func (x *Explorer) breakers(ctx context.Context) (any, string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(x.cfg.AdminURL, "/")+"/api/health", nil)
	if err != nil {
		return nil, err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	var h struct {
		Breakers json.RawMessage `json:"breakers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, err.Error()
	}
	return h.Breakers, ""
}

//go:embed api.txt
var apiDoc string
