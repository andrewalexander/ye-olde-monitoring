package forensics

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/andrewalexander/ye-olde-monitoring/internal/guard"
)

// tripRegex reads the dnscount-trip jail's failregex from nix/guard.nix, with
// the default breakers filled in and <HOST> as a capture group, so the Go
// line and the jail can't drift apart.
func tripRegex(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile("../../nix/guard.nix")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`tripRegex = ''(.*)'';`).FindSubmatch(b)
	if m == nil {
		t.Fatal("tripRegex not found in nix/guard.nix")
	}
	re := strings.Replace(string(m[1]), `${concatStringsSep "|" cfg.tripBreakers}`, "counter|ingest", 1)
	re = strings.Replace(re, "<HOST>", `(\S+)`, 1)
	return regexp.MustCompile(re)
}

func TestTripLineMatchesJail(t *testing.T) {
	re := tripRegex(t)
	for _, c := range []struct {
		trip guard.Trip
		ban  string // "" means no ban
	}{
		{guard.Trip{Breaker: "counter", Key: "203.0.113.7", Reason: "rate"}, "203.0.113.7"},
		{guard.Trip{Breaker: "ingest", Key: "2001:db8::7", Reason: "bad_token"}, "2001:db8::7"},
		{guard.Trip{Breaker: "syslog-not-allowed", Key: "203.0.113.8", Reason: "not_allowed"}, ""}, // not a default
		{guard.Trip{Breaker: "counter", Key: guard.Global, Reason: "map_full"}, ""},                // never ban everyone
	} {
		line, ok := TripLine(c.trip)
		got := ""
		if ok {
			// As the journal sees it: the logger's prefix and timestamp first.
			if m := re.FindStringSubmatch("forensics: 2026/11/06 12:00:00 " + line); m != nil {
				got = m[1]
			}
		}
		if got != c.ban {
			t.Errorf("%+v: line %q bans %q, want %q", c.trip, line, got, c.ban)
		}
	}
}
