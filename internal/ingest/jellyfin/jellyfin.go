// Package jellyfin reads Jellyfin's log (as journalctl prints it) for refused
// logins, so the explorer can show which names an address tried.
package jellyfin

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

// Jellyfin parses lines like
//
//	2026-10-05T19:56:53-04:00 host jellyfin[9130]: [19:56:53] [INF] [93] Jellyfin.Server.Implementations.Users.UserManager: Authentication request for admin has been denied (IP: 203.0.113.9).
//
// The address is the real visitor's only when Caddy is a known proxy to
// Jellyfin; the same line feeds the guard's jellyfin jail.
type Jellyfin struct{}

// Unguarded: almost all of Jellyfin's log is other chatter, which is skipped.
func (Jellyfin) Unguarded() {}

var deniedRE = regexp.MustCompile(`Authentication request for (.*) has been denied \(IP: ([^)\s]+)\)`)

func (Jellyfin) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	if err != nil || !strings.HasPrefix(strings.ToLower(h.Prog), "jellyfin") {
		return ingest.Record{}, ingest.ErrSkip
	}
	m := deniedRE.FindStringSubmatch(h.Msg)
	if m == nil {
		return ingest.Record{}, ingest.ErrSkip
	}
	ip, err := netip.ParseAddr(m[2])
	if err != nil {
		return ingest.Record{}, errors.New("jellyfin denied login without a valid address")
	}
	return ingest.Record{Auth: &ingest.AuthFailure{TS: h.TS, Source: "jellyfin", IP: ip.Unmap().String(), User: m[1]}}, nil
}
