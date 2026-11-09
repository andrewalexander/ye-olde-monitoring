// Package hit defines a single recorded web request and the helpers for
// extracting, cleaning and validating one.
package hit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxField is the longest any free-text field is allowed to be once stored.
const MaxField = 2048

// Hit is one request to a site. Hash is the dedup key: a random ID for
// middleware hits (so retried batches are idempotent) or a hash of the raw
// log line for imported logs.
type Hit struct {
	Hash         string    `json:"id"`
	TS           time.Time `json:"ts"`
	Site         string    `json:"site"`
	Source       string    `json:"source"`
	ClientIP     string    `json:"client_ip"`
	ForwardedFor string    `json:"forwarded_for,omitempty"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	Query        string    `json:"query,omitempty"`
	Status       int       `json:"status"`
	Bytes        int64     `json:"bytes"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Referer      string    `json:"referer,omitempty"`
}

// NewID returns a random dedup key for a hit that has no raw line.
func NewID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var siteRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidSite reports whether s is usable as a site name.
func ValidSite(s string) bool { return siteRE.MatchString(s) }

// Validate checks a hit received from an untrusted sender.
func (h *Hit) Validate(now time.Time) error {
	switch {
	case h.Hash == "" || len(h.Hash) > 128:
		return errors.New("id: missing or too long")
	case !ValidSite(h.Site):
		return fmt.Errorf("site: %q is not [A-Za-z0-9._-]{1,64}", h.Site)
	case h.TS.IsZero():
		return errors.New("ts: missing")
	case h.TS.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)):
		return errors.New("ts: before 2000")
	case h.TS.After(now.Add(5 * time.Minute)):
		return errors.New("ts: in the future")
	case h.Status != 0 && (h.Status < 100 || h.Status > 599):
		return fmt.Errorf("status: %d out of range", h.Status)
	case h.Bytes < 0:
		return errors.New("bytes: negative")
	}
	if _, err := netip.ParseAddr(h.ClientIP); err != nil {
		return fmt.Errorf("client_ip: %q is not an IP", h.ClientIP)
	}
	return nil
}

// Sanitize truncates free-text fields and strips control characters so odd
// requests are still recorded but can't bloat or garble the database.
func (h *Hit) Sanitize() {
	for _, f := range []*string{&h.Site, &h.Source, &h.ClientIP, &h.ForwardedFor, &h.Method,
		&h.Host, &h.Path, &h.Query, &h.UserAgent, &h.Referer} {
		*f = Clean(*f, MaxField)
	}
	h.Query = RedactQuery(h.Query)
	if base, rest, ok := strings.Cut(h.Referer, "?"); ok {
		q, frag, hasFrag := strings.Cut(rest, "#")
		h.Referer = base + "?" + RedactQuery(q)
		if hasFrag {
			h.Referer += "#" + frag
		}
	}
	h.TS = h.TS.UTC()
}

// secretParams are query keys whose values are credentials (Jellyfin and
// Emby clients put api_key in image and stream URLs). Compared lowercased.
var secretParams = map[string]bool{
	"api_key": true, "apikey": true, "x-emby-token": true, "x-mediabrowser-token": true,
	"token": true, "access_token": true, "auth": true, "password": true,
	"sig": true, "signature": true,
}

// RedactQuery replaces the values of secret-looking parameters in a raw
// query string with REDACTED, leaving everything else byte for byte.
func RedactQuery(q string) string {
	if q == "" {
		return q
	}
	parts := strings.Split(q, "&")
	for i, p := range parts {
		k, _, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if secretParams[strings.ToLower(k)] {
			parts[i] = k + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}

// Clean replaces invalid UTF-8 and control characters with '?' and truncates
// to max bytes.
func Clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// FromRequest builds a hit from an incoming request. Status and Bytes are
// left for the caller to fill in.
func FromRequest(r *http.Request, site string, trusted []netip.Prefix) Hit {
	ip, xff := ClientIP(r, trusted)
	return Hit{
		Hash:         NewID(),
		TS:           time.Now().UTC(),
		Site:         site,
		Source:       "middleware",
		ClientIP:     ip,
		ForwardedFor: xff,
		Method:       r.Method,
		Host:         r.Host,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		UserAgent:    r.UserAgent(),
		Referer:      r.Referer(),
	}
}

// ClientIP returns the best guess at the real client address and the raw
// forwarding chain. Forwarding headers are only believed when the direct peer
// is in trusted; otherwise anyone could claim any address.
func ClientIP(r *http.Request, trusted []netip.Prefix) (ip, chain string) {
	chain = r.Header.Get("X-Forwarded-For")
	peer := RemoteAddr(r)
	if !inAny(peer, trusted) {
		return peer, chain
	}
	// Walk right to left, skipping our own proxies; the first untrusted hop
	// is the client. If every hop is trusted (a LAN visitor when the trusted
	// range covers the LAN), the leftmost one is.
	hops := strings.Split(chain, ",")
	leftmost := ""
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		if !inAny(h, trusted) {
			if _, err := netip.ParseAddr(h); err == nil {
				return h, chain
			}
			leftmost = ""
			break
		}
		leftmost = h
	}
	if leftmost != "" {
		return leftmost, chain
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		if _, err := netip.ParseAddr(real); err == nil {
			return real, chain
		}
	}
	return peer, chain
}

// RemoteAddr is the direct peer's IP without the port.
func RemoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func inAny(ip string, nets []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && InPrefixes(a, nets)
}

// InPrefixes says whether a (IPv4-mapped or not) is in any of nets.
func InPrefixes(a netip.Addr, nets []netip.Prefix) bool {
	a = a.Unmap()
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// ParsePrefixes parses a comma-separated list of CIDRs or bare IPs.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
