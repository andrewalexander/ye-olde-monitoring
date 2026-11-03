package store

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"dnscount/hit"
)

// ParseSince turns "24h", "7d", "30m", an RFC 3339 time or a date
// (2006-01-02) into an absolute time. Empty means the beginning of time.
func ParseSince(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		if days, err := strconv.Atoi(n); err == nil {
			return now.AddDate(0, 0, -days), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("since: %q is not a duration (24h, 7d), RFC 3339 time or date", s)
}

// KV is one row of a grouped report. Keys holds each column's value when
// grouping by several, with Key tab-joining them. First is only set for RankNew.
type KV struct {
	Key   string    `json:"key"`
	Keys  []string  `json:"keys,omitempty"`
	Count int64     `json:"count"`
	First time.Time `json:"first,omitzero"`
}

// Rank picks which rows of a grouped report come back.
type Rank string

const (
	RankTop    Rank = "top"    // most common first
	RankBottom Rank = "bottom" // rarest first
	RankNew    Rank = "new"    // first seen inside the window, newest first
)

// GroupQuery asks for a grouped report. Since is the window for every rank, but
// RankNew counts each row's whole history, so "new" means never seen before Since.
type GroupQuery struct {
	By       string // one column, or several separated by commas
	Site, IP string // hits only; empty matches everything
	Since    time.Time
	Limit    int
	Rank     Rank
}

// BadQueryError is a request for a report that doesn't exist, as opposed to a
// failure running it.
type BadQueryError string

func (e BadQueryError) Error() string { return string(e) }

// Seen is a count with first/last timestamps.
type Seen struct {
	Count int64     `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

var hitColumns = map[string]string{
	"ip": "client_ip", "path": "path", "ua": "user_agent", "site": "site",
	"host": "host", "status": "status", "method": "method", "referer": "referer",
}

// TopHits groups hits by one or more of ip|path|ua|site|host|status|method|referer.
func (s *Store) TopHits(q GroupQuery) ([]KV, error) {
	var cols []string
	for _, by := range strings.Split(q.By, ",") {
		col, ok := hitColumns[by]
		if !ok {
			return nil, BadQueryError(fmt.Sprintf("can't group hits by %q", by))
		}
		cols = append(cols, `CAST(`+col+` AS TEXT)`)
	}
	return s.group(q, `hits`, cols, `(? = '' OR site = ?) AND (? = '' OR client_ip = ?)`,
		q.Site, q.Site, q.IP, q.IP)
}

// group runs a grouped report, keeping each row's filter in filter/args.
func (s *Store) group(q GroupQuery, table string, cols []string, filter string, args ...any) ([]KV, error) {
	if q.Limit <= 0 {
		q.Limit = 25
	}
	// Columns are referred to by position: the keys, then the count, then the time.
	n := len(cols)
	keys := make([]string, n)
	for i := range keys {
		keys[i] = strconv.Itoa(i + 1)
	}
	byKeys := strings.Join(keys, ", ")
	count, first := strconv.Itoa(n+1), strconv.Itoa(n+2)
	stmt := `SELECT ` + strings.Join(cols, ", ") + `, count(*), min(ts) FROM ` + table + ` WHERE ` + filter
	switch q.Rank {
	case RankTop, "":
		stmt += ` AND ts >= ? GROUP BY ` + byKeys + ` ORDER BY ` + count + ` DESC, ` + byKeys + ` LIMIT ?`
	case RankBottom:
		stmt += ` AND ts >= ? GROUP BY ` + byKeys + ` ORDER BY ` + count + `, ` + byKeys + ` LIMIT ?`
	case RankNew:
		stmt += ` GROUP BY ` + byKeys + ` HAVING min(ts) >= ? ORDER BY ` + first + ` DESC, ` + byKeys + ` LIMIT ?`
	default:
		return nil, BadQueryError(fmt.Sprintf("unknown order %q (top|bottom|new)", q.Rank))
	}
	rows, err := s.db.Query(stmt, append(args, fmtTime(q.Since), q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KV
	for rows.Next() {
		var kv KV
		var firstTS string
		vals := make([]sql.NullString, n)
		dest := make([]any, 0, n+2)
		for i := range vals {
			dest = append(dest, &vals[i])
		}
		dest = append(dest, &kv.Count, &firstTS)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		parts := make([]string, n)
		for i, v := range vals {
			parts[i] = v.String
		}
		kv.Key = strings.Join(parts, "\t")
		if n > 1 {
			kv.Keys = parts
		}
		if q.Rank == RankNew {
			kv.First = parseTime(firstTS)
		}
		out = append(out, kv)
	}
	return out, rows.Err()
}

// HitFilter selects hits; empty fields match everything.
type HitFilter struct {
	Site, IP string
	Since    time.Time
	Limit    int
}

// Hits returns matching hits, newest first.
func (s *Store) Hits(f HitFilter) ([]hit.Hit, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := s.db.Query(`SELECT line_hash, ts, site, source, client_ip, forwarded_for, method, host, path,
		query, status, bytes, user_agent, referer FROM hits
		WHERE ts >= ? AND (? = '' OR site = ?) AND (? = '' OR client_ip = ?)
		ORDER BY ts DESC LIMIT ?`, fmtTime(f.Since), f.Site, f.Site, f.IP, f.IP, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hit.Hit
	for rows.Next() {
		var h hit.Hit
		var ts string
		if err := rows.Scan(&h.Hash, &ts, &h.Site, &h.Source, &h.ClientIP, &h.ForwardedFor, &h.Method,
			&h.Host, &h.Path, &h.Query, &h.Status, &h.Bytes, &h.UserAgent, &h.Referer); err != nil {
			return nil, err
		}
		h.TS = parseTime(ts)
		out = append(out, h)
	}
	return out, rows.Err()
}

// domainMatch matches a domain and all its subdomains without LIKE, since
// '_' is legal in DNS names and would be a wildcard.
const domainMatch = `(domain = ?1 OR (length(domain) > length(?1) AND substr(domain, -length(?1)-1) = '.' || ?1))`

// ClientLookups is one client's lookups of a domain.
type ClientLookups struct {
	ClientIP   string `json:"client_ip"`
	ClientName string `json:"client_name,omitempty"`
	Seen
}

// DNSByDomain: which clients looked up domain (or a subdomain), how many
// times, first and last.
func (s *Store) DNSByDomain(domain string, since time.Time) ([]ClientLookups, error) {
	rows, err := s.db.Query(`SELECT client_ip, max(client_name), count(*), min(ts), max(ts) FROM dns_queries
		WHERE `+domainMatch+` AND ts >= ?2 GROUP BY client_ip ORDER BY 3 DESC, 1`, domain, fmtTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientLookups
	for rows.Next() {
		var c ClientLookups
		var first, last string
		if err := rows.Scan(&c.ClientIP, &c.ClientName, &c.Count, &first, &last); err != nil {
			return nil, err
		}
		c.First, c.Last = parseTime(first), parseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// DomainLookups is one domain a client looked up.
type DomainLookups struct {
	Domain string `json:"domain"`
	Seen
}

// DNSByClient: which domains a client looked up.
func (s *Store) DNSByClient(ip string, since time.Time, limit int) ([]DomainLookups, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT domain, count(*), min(ts), max(ts) FROM dns_queries
		WHERE client_ip = ? AND ts >= ? GROUP BY domain ORDER BY 2 DESC, 1 LIMIT ?`, ip, fmtTime(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainLookups
	for rows.Next() {
		var d DomainLookups
		var first, last string
		if err := rows.Scan(&d.Domain, &d.Count, &first, &last); err != nil {
			return nil, err
		}
		d.First, d.Last = parseTime(first), parseTime(last)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DNSTop groups lookups by domain, client or both.
func (s *Store) DNSTop(q GroupQuery) ([]KV, error) {
	var cols []string
	for _, by := range strings.Split(q.By, ",") {
		col := map[string]string{"domain": "domain", "client": "client_ip"}[by]
		if col == "" {
			return nil, BadQueryError(fmt.Sprintf("can't group dns by %q (domain|client)", by))
		}
		cols = append(cols, col)
	}
	return s.group(q, `dns_queries`, cols, `1`)
}

// ConnStat is a group of firewall-logged connections.
type ConnStat struct {
	ClientIP string `json:"client_ip"`
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Proto    string `json:"proto"`
	Action   string `json:"action"`
	Seen
}

// ConnsForDomain joins answers for domain to connections that went to those
// addresses: "looked it up, then actually connected".
func (s *Store) ConnsForDomain(domain string, since time.Time) ([]ConnStat, error) {
	return s.conns(`SELECT client_ip, dst_ip, dst_port, proto, action, count(*), min(ts), max(ts) FROM connections
		WHERE dst_ip IN (SELECT DISTINCT answer FROM dns_replies WHERE `+domainMatch+`) AND ts >= ?2
		GROUP BY 1,2,3,4,5 ORDER BY 6 DESC`, domain, fmtTime(since))
}

// ConnsForClient groups a client's logged connections.
func (s *Store) ConnsForClient(ip string, since time.Time) ([]ConnStat, error) {
	return s.conns(`SELECT client_ip, dst_ip, dst_port, proto, action, count(*), min(ts), max(ts) FROM connections
		WHERE client_ip = ? AND ts >= ? GROUP BY 1,2,3,4,5 ORDER BY 6 DESC`, ip, fmtTime(since))
}

func (s *Store) conns(q string, args ...any) ([]ConnStat, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnStat
	for rows.Next() {
		var c ConnStat
		var first, last string
		if err := rows.Scan(&c.ClientIP, &c.DstIP, &c.DstPort, &c.Proto, &c.Action, &c.Count, &first, &last); err != nil {
			return nil, err
		}
		c.First, c.Last = parseTime(first), parseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// IPHistory is everything we have on one address, for forensics.
type IPHistory struct {
	Hits        Seen  `json:"hits"`
	DNSQueries  Seen  `json:"dns_queries"`
	Connections Seen  `json:"connections"`
	Trips       int64 `json:"previous_trips"`
}

func (s *Store) IPHistory(ip string) (IPHistory, error) {
	var h IPHistory
	for _, x := range []struct {
		dst *Seen
		q   string
	}{
		{&h.Hits, `SELECT count(*), coalesce(min(ts),''), coalesce(max(ts),'') FROM hits WHERE client_ip = ?`},
		{&h.DNSQueries, `SELECT count(*), coalesce(min(ts),''), coalesce(max(ts),'') FROM dns_queries WHERE client_ip = ?`},
		{&h.Connections, `SELECT count(*), coalesce(min(ts),''), coalesce(max(ts),'') FROM connections WHERE client_ip = ?1 OR dst_ip = ?1`},
	} {
		var first, last string
		if err := s.db.QueryRow(x.q, ip).Scan(&x.dst.Count, &first, &last); err != nil {
			return h, err
		}
		x.dst.First, x.dst.Last = parseTime(first), parseTime(last)
	}
	err := s.db.QueryRow(`SELECT count(*) FROM breaker_trips WHERE key = ?`, ip).Scan(&h.Trips)
	return h, err
}
