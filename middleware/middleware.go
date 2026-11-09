// Package middleware records every request a Go web app serves. Drop it in
// front of your handler with Wrap and pick a sink: LocalSink writes to a
// SQLite file in-process, RemoteSink ships hits to a central `dnscount serve`.
//
//	sink := middleware.NewRemoteSink("https://collector:8080/ingest", token)
//	defer sink.Close()
//	http.ListenAndServe(":8000", middleware.Wrap(mux, sink, middleware.Options{Site: "blog"}))
package middleware

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
)

// Sink receives hits. Record must never block the request.
type Sink interface {
	Record(hit.Hit)
}

type Options struct {
	Site string
	// TrustedProxies are the only peers whose X-Forwarded-For/X-Real-IP is
	// believed. Leave empty if clients connect directly.
	TrustedProxies []netip.Prefix
	// SkipPaths are path prefixes not to record (health checks...).
	SkipPaths []string
}

// Wrap records each request to next in sink.
func Wrap(next http.Handler, sink Sink, opts Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range opts.SkipPaths {
			if strings.HasPrefix(r.URL.Path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		h := hit.FromRequest(r, opts.Site, opts.TrustedProxies)
		rw := &recorder{ResponseWriter: w}
		defer func() {
			h.Status, h.Bytes = rw.status, rw.bytes
			if h.Status == 0 {
				h.Status = http.StatusOK
			}
			h.Sanitize()
			sink.Record(h)
		}()
		next.ServeHTTP(rw, r)
	})
}

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush/Hijack on the real writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
