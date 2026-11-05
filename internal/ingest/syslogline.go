package ingest

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Header is the parsed front of a syslog-style line.
type Header struct {
	TS   time.Time
	Host string // empty when the line has no hostname (e.g. Pi-hole's own log)
	Prog string // "dnsmasq", "kernel", ...
	Msg  string
}

var (
	tagRE     = regexp.MustCompile(`^([A-Za-z0-9_./-]+)(\[\d+\])?:$`)
	errNoHead = errors.New("not a syslog line")
)

// ParseHeader understands the three shapes we see from UniFi, Pi-hole and
// rsyslog, with or without a leading <PRI>:
//
//	Oct 27 12:00:01 [host] [host] prog[pid]: msg   (RFC 3164 / plain log files)
//	2026-10-27T12:00:01.123-07:00 [host] prog[pid]: msg   (rsyslog ISO files)
//	1 2026-10-27T12:00:01.123Z host prog pid msgid - msg  (RFC 5424)
//
// RFC 3164 has no year; it's taken from now and rolled back a year if that
// would put the line more than a day in the future (December logs read in
// January).
func ParseHeader(line string, now time.Time) (Header, error) {
	line = StripPRI(strings.TrimSpace(line))
	if strings.HasPrefix(line, "1 ") {
		return parse5424(line[2:])
	}
	var h Header
	var rest string
	if len(line) >= 16 && line[3] == ' ' && line[15] == ' ' {
		ts, err := time.ParseInLocation(time.Stamp, line[:15], now.Location())
		if err != nil {
			return h, errNoHead
		}
		withYear := func(y int) time.Time {
			return time.Date(y, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, now.Location())
		}
		ts = withYear(now.Year())
		if ts.After(now.Add(24 * time.Hour)) {
			ts = withYear(now.Year() - 1)
		}
		h.TS, rest = ts, line[16:]
	} else {
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			return h, errNoHead
		}
		ts, err := time.Parse(time.RFC3339Nano, line[:sp])
		if err != nil {
			return h, errNoHead
		}
		h.TS, rest = ts, line[sp+1:]
	}
	// The tag can follow no host, a host, or (UniFi remote logging) the host
	// twice.
	for i := 0; i < 3; i++ {
		f, r, _ := strings.Cut(rest, " ")
		if m := tagRE.FindStringSubmatch(f); m != nil {
			h.Prog, h.Msg = m[1], r
			return h, nil
		}
		if i == 0 {
			h.Host = f
		}
		rest = r
	}
	return h, errNoHead
}

func parse5424(s string) (Header, error) {
	// TIMESTAMP HOST APP PROCID MSGID SD MSG
	f := strings.SplitN(s, " ", 7)
	if len(f) < 6 {
		return Header{}, errNoHead
	}
	ts, err := time.Parse(time.RFC3339Nano, f[0])
	if err != nil {
		return Header{}, errNoHead
	}
	h := Header{TS: ts, Host: nilDash(f[1]), Prog: nilDash(f[2])}
	if len(f) == 7 {
		msg := f[6]
		if f[5] != "-" && strings.HasPrefix(f[5], "[") {
			// Structured data can contain spaces; skip to the closing "] ".
			if i := strings.Index(f[5]+" "+msg, "] "); i >= 0 {
				msg = (f[5] + " " + msg)[i+2:]
			}
		}
		h.Msg = strings.TrimPrefix(msg, "\ufeff")
	}
	return h, nil
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
