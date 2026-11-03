// Package f2b reads fail2ban's own log (as journalctl prints it) into
// ingest.Ban records, so dnscount can check that each ban actually held.
package f2b

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dnscount/ingest"
)

// Fail2ban parses lines like
//
//	2026-11-02T20:22:47-05:00 host fail2ban.filter[67503]: INFO [jellyfin] Found 203.0.113.9 - 2026-11-02 20:22:47
//	2026-11-02T20:22:58-05:00 host fail2ban.actions[67503]: NOTICE [jellyfin] Increase Ban 203.0.113.9 (2 # 2:00:00 -> 2026-11-02 22:22:58)
//	2026-11-02T20:22:58-05:00 host fail2ban.actions[67503]: NOTICE [jellyfin] Ban 203.0.113.9
//	2026-11-02T21:22:58-05:00 host fail2ban.actions[67503]: NOTICE [jellyfin] Unban 203.0.113.9
//
// "Found" and "Increase Ban" only feed the next Ban (its failure count and
// length); "Restore Ban" (fail2ban re-applying a ban after a restart) counts
// as a ban. It keeps state across lines, so use one per log, in order.
type Fail2ban struct {
	// Ports maps a jail to its port setting. A jail missing here is taken to
	// cover every port.
	Ports map[string]string

	found   map[key]int
	pending map[key]time.Duration
}

type key struct{ jail, ip string }

// Unguarded: most of fail2ban's log is "Found" lines, which are skipped.
func (*Fail2ban) Unguarded() {}

var (
	lineRE     = regexp.MustCompile(`^(?:[A-Z]+\s+)?\[([^\]]+)\]\s+(Found|Ban|Unban|Restore Ban|Increase Ban)\s+(\S+)\s*(.*)$`)
	increaseRE = regexp.MustCompile(`^\(\d+\s*#\s*(?:(\d+) days?, )?(\d+):(\d+):(\d+)`)
)

func (p *Fail2ban) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	if err != nil || !strings.HasPrefix(h.Prog, "fail2ban") {
		return ingest.Record{}, ingest.ErrSkip
	}
	m := lineRE.FindStringSubmatch(strings.TrimSpace(h.Msg))
	if m == nil {
		return ingest.Record{}, ingest.ErrSkip
	}
	jail, what, rest := m[1], m[2], m[4]
	ip, err := netip.ParseAddr(m[3])
	if err != nil {
		return ingest.Record{}, errors.New("fail2ban line without a valid address")
	}
	k := key{jail, ip.String()}
	if p.found == nil {
		p.found, p.pending = map[key]int{}, map[key]time.Duration{}
	}
	switch what {
	case "Found":
		p.found[k]++
		return ingest.Record{}, ingest.ErrSkip
	case "Increase Ban":
		if d, ok := parseIncrease(rest); ok {
			p.pending[k] = d
		}
		return ingest.Record{}, ingest.ErrSkip
	}
	b := &ingest.Ban{TS: h.TS, Event: "ban", Jail: jail, IP: k.ip, Ports: p.Ports[jail]}
	if what == "Unban" {
		b.Event = "unban"
	} else {
		b.Failures, b.BanTime = p.found[k], p.pending[k]
		delete(p.found, k)
		delete(p.pending, k)
	}
	return ingest.Record{Ban: b}, nil
}

// parseIncrease reads "(2 # 2:00:00 -> ...)" or "(3 # 1 day, 0:00:00 -> ...)".
func parseIncrease(s string) (time.Duration, bool) {
	m := increaseRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	var n [4]int
	for i, v := range m[1:] {
		n[i], _ = strconv.Atoi(v)
	}
	return time.Duration(n[0])*24*time.Hour + time.Duration(n[1])*time.Hour +
		time.Duration(n[2])*time.Minute + time.Duration(n[3])*time.Second, true
}

// ParsePorts reads -jail-ports: "jail=ports;jail=ports". Ports keep their
// fail2ban spelling ("80,443,8096", "ssh"), which is why ; separates jails.
func ParsePorts(s string) (map[string]string, error) {
	out := map[string]string{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		jail, ports, ok := strings.Cut(part, "=")
		if !ok || jail == "" {
			return nil, errors.New("want jail=ports;jail=ports, got " + strconv.Quote(part))
		}
		out[jail] = ports
	}
	return out, nil
}
