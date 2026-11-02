// Package ingest holds the record types produced by log parsers and the
// line-by-line driver that feeds a log through a parser.
package ingest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"dnscount/hit"
)

// DNSQuery is one lookup: client asked for domain.
type DNSQuery struct {
	Hash       string
	TS         time.Time
	ClientIP   string
	ClientName string
	Domain     string
	QType      string
	Source     string
}

// DNSReply is one answer/forward/block for a domain.
type DNSReply struct {
	Hash   string
	TS     time.Time
	Domain string
	Answer string
	Status string
	Source string
}

// Conn is one firewall-logged connection attempt.
type Conn struct {
	Hash     string
	TS       time.Time
	ClientIP string
	DstIP    string
	DstPort  int
	Proto    string
	Action   string
	Rule     string
	Source   string
}

// Record is whatever one log line produced; any field may be nil.
type Record struct {
	Hit   *hit.Hit
	Query *DNSQuery
	Reply *DNSReply
	Conn  *Conn
}

// ErrSkip means the line is fine but isn't something this parser records
// (other daemons, DHCP chatter, blank lines...). It is not counted as bad.
var ErrSkip = errors.New("skip")

// LineParser turns one log line into a record. now is used to infer missing
// years. It returns ErrSkip for irrelevant lines and any other error for
// lines that look like they should parse but don't.
type LineParser interface {
	ParseLine(line string, now time.Time) (Record, error)
}

// Stats summarizes a run over a log.
type Stats struct {
	Lines, Records, Skipped, Bad int
}

// GuardLines and GuardBadRatio implement the wrong-format guard: if the first
// GuardLines lines are more than GuardBadRatio unusable, stop early.
const (
	GuardLines    = 1000
	GuardBadRatio = 0.9
)

// MaxLine is the longest line read; longer ones are counted bad.
const MaxLine = 64 * 1024

// Run feeds r through p line by line and calls emit for each record.
func Run(r io.Reader, p LineParser, now time.Time, emit func(Record) error) (Stats, error) {
	var st Stats
	dd := NewDeduper()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLine)
	for sc.Scan() {
		st.Lines++
		rec, err := p.ParseLine(sc.Text(), now)
		switch {
		case errors.Is(err, ErrSkip):
			st.Skipped++
		case err != nil:
			st.Bad++
		default:
			st.Records++
			rec.SetHash(dd.Key(sc.Text()))
			if err := emit(rec); err != nil {
				return st, err
			}
		}
		if st.Lines == GuardLines && float64(st.Bad+st.Skipped) > GuardBadRatio*float64(st.Lines) {
			return st, fmt.Errorf("%d of the first %d lines were unusable; wrong -format?", st.Bad+st.Skipped, st.Lines)
		}
	}
	return st, sc.Err()
}

// Deduper hands out dedup keys for raw lines. Identical lines are legit
// (a client asking for the same name twice in one second), so the n-th copy
// of a line gets hash(line, n). Feeding the same log again in the same order
// produces the same keys, which is what makes re-imports idempotent. Only
// the most recent dedupWindow distinct lines are remembered.
type Deduper struct {
	seen  map[string]int
	order []string
	next  int
}

const dedupWindow = 4096

func NewDeduper() *Deduper {
	return &Deduper{seen: map[string]int{}, order: make([]string, dedupWindow)}
}

// Key returns the dedup key for line. Surrounding whitespace and a syslog
// <PRI> prefix are ignored so a line read from a file and the same line
// received over syslog get the same key.
func (d *Deduper) Key(line string) string {
	line = StripPRI(strings.TrimSpace(line))
	n, ok := d.seen[line]
	if !ok {
		if old := d.order[d.next]; old != "" {
			delete(d.seen, old)
		}
		d.order[d.next] = line
		d.next = (d.next + 1) % dedupWindow
	}
	d.seen[line] = n + 1
	s := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d", line, n))
	return hex.EncodeToString(s[:])
}

// SetHash stamps every part of the record with the same dedup key (they go
// to different tables, so sharing is fine).
func (r *Record) SetHash(h string) {
	if r.Hit != nil {
		r.Hit.Hash = h
	}
	if r.Query != nil {
		r.Query.Hash = h
	}
	if r.Reply != nil {
		r.Reply.Hash = h
	}
	if r.Conn != nil {
		r.Conn.Hash = h
	}
}

// StripPRI removes a leading syslog "<NN>" priority.
func StripPRI(line string) string {
	if strings.HasPrefix(line, "<") {
		if i := strings.IndexByte(line, '>'); i > 1 && i <= 4 {
			return line[i+1:]
		}
	}
	return line
}

// NormDomain lowercases and drops a trailing dot.
func NormDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// Multi tries each parser in turn; the first that doesn't skip wins. UniFi
// syslog is Multi{dns.Dnsmasq{}, fw.IPTables{}}.
type Multi []LineParser

func (m Multi) ParseLine(line string, now time.Time) (Record, error) {
	for _, p := range m {
		rec, err := p.ParseLine(line, now)
		if !errors.Is(err, ErrSkip) {
			return rec, err
		}
	}
	return Record{}, ErrSkip
}
