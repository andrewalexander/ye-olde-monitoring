package ingest

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dnscount/hit"
)

// Combined parses nginx/apache "combined" access logs:
//
//	1.2.3.4 - - [27/Oct/2026:12:00:01 -0700] "GET /a?b=1 HTTP/1.1" 200 512 "ref" "ua"
//
// Request lines that aren't METHOD URI PROTO (TLS handshakes sent to a
// plain-HTTP port, scanner junk) are kept with the raw text as the path:
// that's exactly the traffic worth looking at.
type Combined struct {
	Site string // if empty, the host isn't in the log so "unknown" is used
}

var combinedRE = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`)

func (c Combined) ParseLine(line string, _ time.Time) (Record, error) {
	if strings.TrimSpace(line) == "" {
		return Record{}, ErrSkip
	}
	m := combinedRE.FindStringSubmatch(line)
	if m == nil {
		return Record{}, errors.New("not a combined log line")
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return Record{}, err
	}
	status, _ := strconv.Atoi(m[4])
	size, _ := strconv.ParseInt(m[5], 10, 64)
	h := &hit.Hit{
		TS: ts, Site: orUnknown(c.Site), Source: "access-log", ClientIP: m[1], Status: status, Bytes: size,
		Referer: dash(unescape(m[6])), UserAgent: dash(unescape(m[7])),
	}
	req := unescape(m[3])
	if f := strings.Fields(req); len(f) == 3 && strings.HasPrefix(f[2], "HTTP/") {
		h.Method = f[0]
		h.Path, h.Query, _ = strings.Cut(f[1], "?")
	} else {
		h.Path = req
	}
	return Record{Hit: h}, nil
}

// Caddy parses Caddy's JSON access log (one object per line).
type Caddy struct {
	Site string // overrides the request host when set
}

type caddyLine struct {
	TS      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Status  int     `json:"status"`
	Size    int64   `json:"size"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
}

func (c Caddy) ParseLine(line string, _ time.Time) (Record, error) {
	if strings.TrimSpace(line) == "" {
		return Record{}, ErrSkip
	}
	var l caddyLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		return Record{}, err
	}
	if !strings.HasPrefix(l.Logger, "http.log.access") {
		return Record{}, ErrSkip
	}
	ip := l.Request.ClientIP
	if ip == "" {
		ip = l.Request.RemoteIP
	}
	sec, frac := math.Modf(l.TS)
	h := &hit.Hit{
		TS: time.Unix(int64(sec), int64(frac*1e9)), Source: "caddy", ClientIP: ip,
		Method: l.Request.Method, Host: l.Request.Host, Status: l.Status, Bytes: l.Size,
		UserAgent: first(l.Request.Headers["User-Agent"]), Referer: first(l.Request.Headers["Referer"]),
		ForwardedFor: first(l.Request.Headers["X-Forwarded-For"]),
	}
	h.Path, h.Query, _ = strings.Cut(l.Request.URI, "?")
	h.Site = c.Site
	if h.Site == "" {
		h.Site = siteFromHost(l.Request.Host)
	}
	return Record{Hit: h}, nil
}

func siteFromHost(host string) string {
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	if hit.ValidSite(host) {
		return host
	}
	return "unknown"
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// unescape undoes nginx's \" and \xNN escaping in quoted fields.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if s[i+1] == 'x' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}
