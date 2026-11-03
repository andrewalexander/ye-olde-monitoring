package store

import (
	"net"
	"net/netip"
	"strings"

	"dnscount/hit"
)

// Host kinds: how a client addressed us.
const (
	HostName = "name" // by hostname, as a browser or app with the site's URL does
	HostIP   = "ip"   // by bare IP address: typically a scanner sweeping addresses
)

// HostKind says whether a Host header is a name or an IP address (with or
// without a port). It's "" for an empty header.
func HostKind(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if _, err := netip.ParseAddr(host); err == nil {
		return HostIP
	}
	return HostName
}

// hostIsIP is HostKind(host) == "ip" in SQL: an IPv6 literal in brackets, or
// only digits, dots and colons (an IPv4 address, maybe with a port).
const hostIsIP = `(host GLOB '[[]*' OR (host GLOB '*.*' AND NOT host GLOB '*[^0-9.:]*'))`

// HitRow is a hit plus how it addressed us.
type HitRow struct {
	hit.Hit
	HostKind string `json:"host_kind"`
}

// WithHostKind annotates hits.
func WithHostKind(hits []hit.Hit) []HitRow {
	out := make([]HitRow, len(hits))
	for i, h := range hits {
		out[i] = HitRow{h, HostKind(h.Host)}
	}
	return out
}
