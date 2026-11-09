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

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

// Fail2ban parses lines like
//
//	2026-11-02T20:22:47-05:00 host fail2ban.filter[67503]: INFO [jellyfin] Found 203.0.113.9 - 2026-11-02 20:22:47
//	2026-11-02T20:22:58-05:00 host fail2ban.actions[67503]: NOTICE [jellyfin] Increase Ban 203.0.113.9 (2 # 2:00:00 -> 2026-11-02 22:22:58)
//	2026-11-02T20:22:58-05:00 host fail2ban.actions[67503]: NOTICE [jellyfin] Ban 203.0.113.9
//	2026-11-02T21:22:58-05:00 host fail2ban.actions[67503]: NOTICE [jellyfin] Unban 203.0.113.9
//
//	2026-11-02T21:09:38-05:00 host fail2ban.filter[67503]: INFO [jellyfin] Ignore 192.168.1.230 by ip
//
// "Found" lines feed the next Ban: its failure count and the times of the
// lines that matched (Ban.Found). "Ignore" lines are a match from an exempt
// address (one per line, with no time of its own); once an address has a
// jail's maxretry of them within its findtime (Limits), that's an "ignored"
// event: it would have been banned. "by ignoreself" (this host) is skipped.
// "Increase Ban" gives
// a ban's length: fail2ban 1.1 logs it just after the Ban, as an "increase"
// record the store applies to that ban; older versions log it just before,
// so it's also kept for the next Ban. "Restore Ban" (fail2ban re-applying a
// ban after a restart) counts as a ban. It keeps state across lines, so use
// one per log, in order.
type Fail2ban struct {
	// Ports maps a jail to its port setting. A jail missing here is taken to
	// cover every port.
	Ports map[string]string
	// Limits is each jail's maxretry and findtime, for Ignore lines. A jail
	// missing here gets fail2ban's NixOS defaults (DefaultLimit).
	Limits map[string]Limit

	found   map[key][]time.Time
	ignored map[key][]time.Time
	pending map[key]increase
}

// Limit is how many matches within FindTime make a ban.
type Limit struct {
	MaxRetry int
	FindTime time.Duration
}

// DefaultLimit is NixOS's fail2ban default: 3 matches in 10 minutes.
var DefaultLimit = Limit{MaxRetry: 3, FindTime: 10 * time.Minute}

// LimitFor is jail's limit, or DefaultLimit.
func (p *Fail2ban) LimitFor(jail string) Limit {
	if l, ok := p.Limits[jail]; ok {
		return l
	}
	return DefaultLimit
}

type increase struct {
	at  time.Time
	len time.Duration
}

type key struct{ jail, ip string }

// Unguarded: most of fail2ban's log is "Found" lines, which are skipped.
func (*Fail2ban) Unguarded() {}

var (
	lineRE     = regexp.MustCompile(`^(?:[A-Z]+\s+)?\[([^\]]+)\]\s+(Found|Ban|Unban|Restore Ban|Increase Ban|Ignore)\s+(\S+)\s*(.*)$`)
	increaseRE = regexp.MustCompile(`^\(\d+\s*#\s*([^)>]*?)\s*(?:->|\))`)
	clockRE    = regexp.MustCompile(`^(?:(\d+) days?, )?(\d+):(\d+):(\d+)$`)
	unitRE     = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*([wdhms])`)
	foundRE    = regexp.MustCompile(`^-\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)`)
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
		p.found, p.ignored, p.pending = map[key][]time.Time{}, map[key][]time.Time{}, map[key]increase{}
	}
	switch what {
	case "Found":
		// The matched line's own time, in the zone the journal printed.
		at := h.TS
		if m := foundRE.FindStringSubmatch(rest); m != nil {
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], h.TS.Location()); err == nil {
				at = t
			}
		}
		p.found[k] = append(p.found[k], at)
		return ingest.Record{}, ingest.ErrSkip
	case "Ignore":
		if strings.Contains(rest, "ignoreself") {
			return ingest.Record{}, ingest.ErrSkip
		}
		lim := p.LimitFor(jail)
		times := append(p.ignored[k], h.TS)
		for len(times) > 0 && lim.FindTime > 0 && h.TS.Sub(times[0]) > lim.FindTime {
			times = times[1:]
		}
		if len(times) < max(lim.MaxRetry, 1) {
			p.ignored[k] = times
			return ingest.Record{}, ingest.ErrSkip
		}
		delete(p.ignored, k)
		return ingest.Record{Ban: &ingest.Ban{TS: h.TS, Event: "ignored", Jail: jail, IP: k.ip, Ports: p.Ports[jail],
			Failures: len(times), Found: times}}, nil
	case "Increase Ban":
		d, ok := parseIncrease(rest)
		if !ok {
			return ingest.Record{}, ingest.ErrSkip
		}
		p.pending[k] = increase{h.TS, d}
		return ingest.Record{Ban: &ingest.Ban{TS: h.TS, Event: "increase", Jail: jail, IP: k.ip, BanTime: d}}, nil
	}
	b := &ingest.Ban{TS: h.TS, Event: "ban", Jail: jail, IP: k.ip, Ports: p.Ports[jail]}
	if what == "Unban" {
		b.Event = "unban"
	} else {
		b.Found = p.found[k]
		b.Failures = len(b.Found)
		// Only an increase logged just before this ban is about it; one from
		// longer ago was already applied to the ban before it.
		if inc, ok := p.pending[k]; ok && h.TS.Sub(inc.at) < time.Minute {
			b.BanTime = inc.len
		}
		delete(p.found, k)
		delete(p.pending, k)
	}
	return ingest.Record{Ban: b}, nil
}

// parseIncrease reads the length in "(2 # 2d -> ...)", "(3 # 1d 12h -> ...)"
// (fail2ban 1.1) or "(2 # 1 day, 0:00:00 -> ...)" (older).
func parseIncrease(s string) (time.Duration, bool) {
	m := increaseRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	if c := clockRE.FindStringSubmatch(m[1]); c != nil {
		var n [4]int
		for i, v := range c[1:] {
			n[i], _ = strconv.Atoi(v)
		}
		return time.Duration(n[0])*24*time.Hour + time.Duration(n[1])*time.Hour +
			time.Duration(n[2])*time.Minute + time.Duration(n[3])*time.Second, true
	}
	return parseDuration(m[1])
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

// ParseLimits reads -jail-limits: "jail=maxretry/findtime;...", findtime as
// fail2ban writes it ("10m", "1d", "1h30m", or seconds).
func ParseLimits(s string) (map[string]Limit, error) {
	out := map[string]Limit{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		jail, v, ok := strings.Cut(part, "=")
		n, ft, ok2 := strings.Cut(v, "/")
		retry, err := strconv.Atoi(strings.TrimSpace(n))
		d, ok3 := parseDuration(strings.TrimSpace(ft))
		if !ok || !ok2 || !ok3 || jail == "" || err != nil {
			return nil, errors.New("want jail=maxretry/findtime;..., got " + strconv.Quote(part))
		}
		out[strings.TrimSpace(jail)] = Limit{MaxRetry: retry, FindTime: d}
	}
	return out, nil
}

// parseDuration reads a fail2ban time: plain seconds, or units like 1d12h.
func parseDuration(s string) (time.Duration, bool) {
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, true
	}
	units := map[string]time.Duration{"w": 7 * 24 * time.Hour, "d": 24 * time.Hour, "h": time.Hour, "m": time.Minute, "s": time.Second}
	var d time.Duration
	parts := unitRE.FindAllStringSubmatch(s, -1)
	for _, u := range parts {
		f, _ := strconv.ParseFloat(u[1], 64)
		d += time.Duration(f * float64(units[u[2]]))
	}
	return d, len(parts) > 0
}
