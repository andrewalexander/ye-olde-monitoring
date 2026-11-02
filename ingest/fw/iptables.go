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

	"dnscount/ingest"
)

// IPTables parses kernel firewall log lines as UniFi writes them for rules
// with logging enabled:
//
//	Oct 27 12:00:01 UDM kernel: [WAN_LOCAL-D-2147483647] IN=eth8 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=5555 DPT=22 ...
//
// The bracketed prefix is the rule name; UniFi encodes the action in it
// (-A- accept, -D- drop, -R- reject). An uptime stamp "[ 1234.567]" before
// it is ignored.
type IPTables struct{}

var (
	uptimeRE = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)
	ruleRE   = regexp.MustCompile(`^\[([^\]]+)\]\s*`)
	actionRE = regexp.MustCompile(`-(A|D|R|RET)-`)
)

var actions = map[string]string{"A": "accept", "D": "drop", "R": "reject", "RET": "return"}

func (IPTables) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	if err != nil || h.Prog != "kernel" {
		return ingest.Record{}, ingest.ErrSkip
	}
	msg := uptimeRE.ReplaceAllString(strings.TrimSpace(h.Msg), "")
	if !strings.Contains(msg, "SRC=") {
		return ingest.Record{}, ingest.ErrSkip
	}
	c := &ingest.Conn{TS: h.TS, Source: "unifi-fw"}
	if m := ruleRE.FindStringSubmatch(msg); m != nil {
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
