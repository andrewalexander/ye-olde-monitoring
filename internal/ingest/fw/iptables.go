// Package fw parses UniFi firewall log lines (iptables LOG target) into
// connections.
package fw

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

// IPTables parses kernel firewall log lines as UniFi writes them for rules
// with logging enabled:
//
//	Oct 27 12:00:01 UDM kernel: [WAN_LOCAL-D-2147483647] IN=eth8 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=5555 DPT=22 ...
//
// Newer UniFi releases send them without the "kernel:" tag, the hostname in
// its place, and a DESCR:
//
//	<13>Nov  6 00:00:01 Router Router [WAN_IN-RET-30005] DESCR="[WAN_IN]Allow Port Forward {Jellyfin" IN=eth3 OUT=br2 ... SRC=... DST=... PROTO=TCP ...
//
// A port forward logs each inbound packet twice: [PREROUTING-DNAT-n] to the
// WAN address, then the forwarded rule to the real destination. Only the
// second is kept. LAN_LOCAL (LAN devices talking to the router itself,
// UniFi's default rules log it) is skipped: it's most of the volume and
// says nothing about the internet.
//
// The bracketed prefix is the rule name; UniFi encodes the action in it
// (-A- accept, -D- drop, -R- reject). An uptime stamp "[ 1234.567]" before
// it is ignored.
//
// It also reads this host's own kernel lines for packets fail2ban rejected
// from a banned address (the guard's dnscount-iptables-log action), as
// journalctl prints them:
//
//	2026-11-09T10:00:00-05:00 host kernel: f2b-caddy-probe: IN=enp1s0 OUT= MAC=... SRC=203.0.113.9 DST=192.0.2.1 ... PROTO=TCP SPT=5555 DPT=443 ...
//
// Those become rule "f2b-<jail>", action reject, source host-fw.
type IPTables struct{}

var (
	uptimeRE = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)
	ruleRE   = regexp.MustCompile(`^\[([^\]]+)\]\s*`)
	f2bRE    = regexp.MustCompile(`^(f2b-[^:\s]+):\s*`)
	actionRE = regexp.MustCompile(`-(A|D|R|RET)-`)
)

var actions = map[string]string{"A": "accept", "D": "drop", "R": "reject", "RET": "return"}

func (IPTables) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	var msg string
	switch {
	case err == nil && h.Prog == "kernel":
		msg = uptimeRE.ReplaceAllString(strings.TrimSpace(h.Msg), "")
		if !strings.Contains(msg, "SRC=") {
			return ingest.Record{}, ingest.ErrSkip
		}
	case !h.TS.IsZero():
		// No program tag: the message is everything from the rule on, and
		// it has to look like a firewall line to count.
		i := strings.Index(line, " [")
		if i < 0 {
			return ingest.Record{}, ingest.ErrSkip
		}
		msg = strings.TrimSpace(line[i+1:])
		if !ruleRE.MatchString(msg) || !strings.Contains(msg, " SRC=") || !strings.Contains(msg, " DST=") || !strings.Contains(msg, " PROTO=") {
			return ingest.Record{}, ingest.ErrSkip
		}
	default:
		return ingest.Record{}, ingest.ErrSkip
	}
	if m := ruleRE.FindStringSubmatch(msg); m != nil {
		if strings.HasPrefix(m[1], "PREROUTING-DNAT") || strings.HasPrefix(m[1], "LAN_LOCAL-") {
			return ingest.Record{}, ingest.ErrSkip // see above
		}
	}
	c := &ingest.Conn{TS: h.TS, Source: "unifi-fw"}
	if m := f2bRE.FindStringSubmatch(msg); m != nil {
		c.Source, c.Rule, c.Action = "host-fw", m[1], "reject"
		msg = msg[len(m[0]):]
	} else if m := ruleRE.FindStringSubmatch(msg); m != nil {
		c.Rule = m[1]
		msg = msg[len(m[0]):]
		if a := actionRE.FindStringSubmatch(c.Rule + "-"); a != nil {
			c.Action = actions[a[1]]
		}
	}
	for _, f := range strings.Fields(msg) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "SRC":
			c.ClientIP = v
		case "DST":
			c.DstIP = v
		case "PROTO":
			c.Proto = strings.ToLower(v)
		case "DPT":
			c.DstPort, _ = strconv.Atoi(v)
		}
	}
	for _, ip := range []*string{&c.ClientIP, &c.DstIP} {
		a, err := netip.ParseAddr(*ip)
		if err != nil {
			return ingest.Record{}, errors.New("firewall line without valid SRC/DST")
		}
		*ip = a.String()
	}
	return ingest.Record{Conn: c}, nil
}
