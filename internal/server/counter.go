// The old-school "you are visitor #000123" image.

package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// counterDigits is the zero-padded width of the counter.
const counterDigits = 6

const (
	cellW = 16
	cellH = 24
	pad   = 2
)

// counterSVG renders n as green digits in black boxes.
func counterSVG(n int64) []byte {
	digits := fmt.Sprintf("%0*d", counterDigits, max(n, 0))
	w := len(digits)*(cellW+pad) + pad
	h := cellH + 2*pad
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s visitors">`,
		w, h, w, h, strconv.FormatInt(n, 10))
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#000"/>`, w, h)
	for i, d := range digits {
		x := pad + i*(cellW+pad)
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="#111" stroke="#444"/>`, x, pad, cellW, cellH)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-family="'Courier New',monospace" font-size="20" font-weight="bold" fill="#3f3" text-anchor="middle">%c</text>`,
			x+cellW/2, pad+cellH-6, d)
	}
	b.WriteString(`</svg>`)
	return []byte(b.String())
}

type cached struct {
	n  int64
	at time.Time
}

// counterHandler serves the visitor counter for an allowed site. It only
// reads: visits are whatever recorded the page loads (Caddy's log, usually),
// and store.Visitors turns those into one number. Each site's number is
// reused for CounterTTL, so a reload storm costs one query a minute.
func (s *Server) counterHandler(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		site := r.URL.Query().Get("site")
		n, ok, err := s.visitors(site)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.cfg.Log.Printf("counter %s: %v", site, err) // still draw the last number
		}
		w.Header().Set("Cache-Control", "no-cache")
		if format == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, n)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(counterSVG(n))
	}
}

// visitors returns site's number, recomputing it when it's older than
// CounterTTL. ok is false for a site not in CounterSites.
func (s *Server) visitors(site string) (n int64, ok bool, err error) {
	s.counterMu.Lock()
	defer s.counterMu.Unlock()
	c, ok := s.counter[site]
	if !ok {
		return 0, false, nil
	}
	now := s.cfg.Now()
	if !c.at.IsZero() && now.Sub(c.at) < s.cfg.CounterTTL {
		return c.n, true, nil
	}
	v, err := s.cfg.Store.Visitors(site)
	if err != nil {
		return c.n, true, err
	}
	s.counter[site] = cached{n: v, at: now}
	return v, true, nil
}
