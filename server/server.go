// Package server is `dnscount serve`: the public counter, the /ingest
// collector for RemoteSinks, and the localhost-only admin API.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"dnscount/breaker"
	"dnscount/counter"
	"dnscount/hit"
	"dnscount/middleware"
	"dnscount/store"
)

const (
	MaxBody      = 1 << 20
	MaxBatch     = 1000
	bodySample   = 2048
	maxErrorsOut = 10
)

type Config struct {
	Store *store.Store
	// Token guards /ingest. Empty disables /ingest entirely.
	Token          string
	TrustedProxies []netip.Prefix
	// CounterPerMinute is how many counter increments one IP gets per minute.
	CounterPerMinute int
	// IngestPerMinute / IngestBadPerMinute limit /ingest per IP.
	IngestPerMinute    int
	IngestBadPerMinute int
	Cooldown           time.Duration
	OnTrip, OnEnd      func(breaker.Trip)
	Now                func() time.Time
	Log                *log.Logger
}

type Server struct {
	cfg     Config
	Counter *breaker.Breaker
	Ingest  *breaker.Breaker
}

func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CounterPerMinute == 0 {
		cfg.CounterPerMinute = 30
	}
	if cfg.IngestPerMinute == 0 {
		cfg.IngestPerMinute = 600
	}
	if cfg.IngestBadPerMinute == 0 {
		cfg.IngestBadPerMinute = 10
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = log.Default()
	}
	mk := func(name string, max, maxBad int) *breaker.Breaker {
		return breaker.New(breaker.Config{
			Name: name, Window: time.Minute, Cooldown: cfg.Cooldown, Max: max, MaxBad: maxBad,
			Now: cfg.Now, OnTrip: cfg.OnTrip, OnEnd: cfg.OnEnd,
		})
	}
	return &Server{
		cfg:     cfg,
		Counter: mk("counter", cfg.CounterPerMinute, 20),
		Ingest:  mk("ingest", cfg.IngestPerMinute, cfg.IngestBadPerMinute),
	}
}

// Public is the internet-facing handler.
func (s *Server) Public() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /counter.svg", s.counter("svg"))
	mux.HandleFunc("GET /counter.txt", s.counter("txt"))
	mux.HandleFunc("GET /counter.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		io.WriteString(w, counter.JS)
	})
	mux.HandleFunc("/ingest", s.ingest)
	return mux
}

func (s *Server) counter(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _ := hit.ClientIP(r, s.cfg.TrustedProxies)
		site := r.URL.Query().Get("site")
		if !hit.ValidSite(site) {
			s.Counter.Bad(ip, "malformed", s.event(r, nil, "bad site"))
			http.Error(w, "site must be [A-Za-z0-9._-]{1,64}", http.StatusBadRequest)
			return
		}
		// Over the limit still gets the image, it just doesn't count, so
		// nobody can pump the counter and the page never shows a broken image.
		if r.URL.Query().Get("noinc") == "" && s.Counter.Allow(ip, s.event(r, nil, "")) {
			h := hit.FromRequest(r, site, s.cfg.TrustedProxies)
			h.TS, h.Source, h.Status, h.Count = s.cfg.Now().UTC(), "counter", http.StatusOK, true
			h.Sanitize()
			if _, err := s.cfg.Store.InsertHits([]hit.Hit{h}); err != nil {
				s.cfg.Log.Printf("counter: %v", err)
			}
		}
		n, err := s.cfg.Store.Counter(site)
		if err != nil {
			s.cfg.Log.Printf("counter: %v", err)
		}
		w.Header().Set("Cache-Control", "no-store")
		if format == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, n)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(counter.SVG(n))
	}
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	ip, _ := hit.ClientIP(r, s.cfg.TrustedProxies)
	if !s.Ingest.Allow(ip, s.event(r, nil, "")) {
		if until, ok := s.Ingest.CooldownUntil(ip); ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(until.Sub(s.cfg.Now()).Seconds())+1))
		}
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	bad := func(code int, reason, msg string, body []byte) {
		s.Ingest.Bad(ip, reason, s.event(r, body, msg))
		http.Error(w, msg, code)
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		bad(http.StatusMethodNotAllowed, "malformed", "POST only", nil)
		return
	}
	if s.cfg.Token == "" || !checkToken(r, s.cfg.Token) {
		bad(http.StatusUnauthorized, "bad_token", "missing or bad bearer token", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			bad(http.StatusRequestEntityTooLarge, "oversize", fmt.Sprintf("body over %d bytes", MaxBody), body)
			return
		}
		bad(http.StatusBadRequest, "malformed", "reading body: "+err.Error(), body)
		return
	}
	var batch middleware.IngestBatch
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil {
		bad(http.StatusBadRequest, "malformed", "bad JSON: "+err.Error(), body)
		return
	}
	if len(batch.Hits) > MaxBatch {
		bad(http.StatusBadRequest, "malformed", fmt.Sprintf("%d hits in batch, max %d", len(batch.Hits), MaxBatch), body)
		return
	}
	var errs []string
	now := s.cfg.Now()
	for i := range batch.Hits {
		if err := batch.Hits[i].Validate(now); err != nil {
			errs = append(errs, fmt.Sprintf("hits[%d]: %v", i, err))
		}
	}
	if len(errs) > 0 {
		if len(errs) > maxErrorsOut {
			errs = append(errs[:maxErrorsOut], fmt.Sprintf("...and %d more", len(errs)-maxErrorsOut))
		}
		bad(http.StatusBadRequest, "malformed", "invalid hits (batch rejected):\n"+strings.Join(errs, "\n"), body)
		return
	}
	for i := range batch.Hits {
		batch.Hits[i].Sanitize()
	}
	n, err := s.cfg.Store.InsertHits(batch.Hits)
	if err != nil {
		s.cfg.Log.Printf("ingest: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	WriteJSON(w, map[string]int{"accepted": n, "duplicates": len(batch.Hits) - n})
}

func checkToken(r *http.Request, want string) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// event builds the breaker event for a request: a short summary for the
// ring buffer and the full detail in case this request is the one that trips.
func (s *Server) event(r *http.Request, body []byte, problem string) breaker.Event {
	ip, xff := hit.ClientIP(r, s.cfg.TrustedProxies)
	sum, _ := json.Marshal(struct {
		Method string `json:"m"`
		URL    string `json:"u"`
		IP     string `json:"ip"`
		XFF    string `json:"xff,omitempty"`
		UA     string `json:"ua,omitempty"`
		Len    int64  `json:"len,omitempty"`
		Err    string `json:"err,omitempty"`
	}{r.Method, hit.Clean(r.RequestURI, 512), ip, hit.Clean(xff, 256), hit.Clean(r.UserAgent(), 256), r.ContentLength, problem})
	return breaker.Event{Data: string(sum), Trigger: RequestDetail(r, ip, body, problem)}
}

// RequestDetail is everything we can say about a request, for trip forensics.
// Credentials are hashed (with length) so trips can be correlated without
// storing secrets.
func RequestDetail(r *http.Request, clientIP string, body []byte, problem string) map[string]any {
	headers := map[string][]string{}
	for k, vs := range r.Header {
		for _, v := range vs {
			switch k {
			case "Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key":
				v = Fingerprint(v)
			default:
				v = hit.Clean(v, hit.MaxField)
			}
			headers[k] = append(headers[k], v)
		}
	}
	d := map[string]any{
		"remote_addr":     r.RemoteAddr,
		"client_ip":       clientIP,
		"x_forwarded_for": r.Header.Get("X-Forwarded-For"),
		"x_real_ip":       r.Header.Get("X-Real-IP"),
		"forwarded":       r.Header.Get("Forwarded"),
		"method":          hit.Clean(r.Method, 64),
		"url":             hit.Clean(r.RequestURI, hit.MaxField),
		"proto":           r.Proto,
		"host":            hit.Clean(r.Host, 256),
		"headers":         headers,
		"content_length":  r.ContentLength,
		"content_type":    r.Header.Get("Content-Type"),
	}
	if r.TLS != nil {
		d["tls"] = map[string]any{
			"version": tls.VersionName(r.TLS.Version),
			"cipher":  tls.CipherSuiteName(r.TLS.CipherSuite),
			"sni":     r.TLS.ServerName,
			"alpn":    r.TLS.NegotiatedProtocol,
		}
	}
	if len(body) > 0 {
		b := body[:min(len(body), bodySample)]
		if utf8.Valid(b) {
			d["body_sample"] = string(b)
		} else {
			d["body_sample_hex"] = hex.EncodeToString(b)
		}
		d["body_bytes_read"] = len(body)
	}
	if problem != "" {
		d["problem"] = problem
	}
	return d
}

// Fingerprint replaces a secret with a short hash and its length.
func Fingerprint(v string) string {
	h := sha256.Sum256([]byte(v))
	return fmt.Sprintf("sha256:%s len=%d", hex.EncodeToString(h[:8]), len(v))
}

func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
