package store

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"dnscount/hit"
	"dnscount/ingest"
)

const insertBan = `INSERT OR IGNORE INTO bans (ts, event, jail, ip, ports, bantime_s, failures, line_hash)
	VALUES (?,?,?,?,?,?,?,?)`

// increaseBan sets the length of the ban fail2ban made just before logging
// "Increase Ban". Applying it twice changes nothing.
const increaseBan = `UPDATE bans SET bantime_s = ? WHERE id = (SELECT id FROM bans
	WHERE event = 'ban' AND jail = ? AND ip = ? AND ts <= ? AND ts >= ? ORDER BY ts DESC, id DESC LIMIT 1)`

func banArgs(b *ingest.Ban) []any {
	return []any{fmtTime(b.TS), b.Event, b.Jail, b.IP, b.Ports, int64(b.BanTime / time.Second), b.Failures, b.Hash}
}

// InsertBan records one ban or unban that didn't come from a log (tests,
// tools). Bans from fail2ban's log go through InsertRecords.
func (s *Store) InsertBan(b ingest.Ban) error {
	if b.Event != "ban" && b.Event != "unban" {
		return fmt.Errorf("event must be ban or unban, not %q", b.Event)
	}
	if net.ParseIP(b.IP) == nil {
		return fmt.Errorf("not an IP address: %q", b.IP)
	}
	if b.Hash == "" {
		b.Hash = hit.NewID()
	}
	_, err := s.db.Exec(insertBan, banArgs(&b)...)
	return err
}

// Ban is a ban paired with the unban that ended it, plus what that IP did to
// our sites around it.
type Ban struct {
	ID         int64         `json:"id"`
	BannedAt   time.Time     `json:"banned_at"`
	UnbannedAt time.Time     `json:"unbanned_at,omitzero"` // zero while still banned
	Jail       string        `json:"jail"`
	IP         string        `json:"ip"`
	Ports      string        `json:"ports"`
	BanTime    time.Duration `json:"bantime_ns"`
	Failures   int           `json:"failures"`
	HitsBefore int64         `json:"hits_24h_before"`
	// HitsDuring counts requests that reached a site on a port the ban covers,
	// while it was in force. Anything above zero means the block leaked.
	HitsDuring int64 `json:"hits_during"`
}

// BanGrace is how long after a ban a request still doesn't count as getting
// through: one already in flight when the rule went in is logged when it
// finishes.
const BanGrace = 5 * time.Second

// BanFilter selects bans; empty fields match everything.
type BanFilter struct {
	Since    time.Time
	IP, Jail string
	Limit    int
}

// Bans lists bans newest first, each with its unban and the hits around it.
func (s *Store) Bans(f BanFilter, now time.Time) ([]Ban, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := s.db.Query(`SELECT b.id, b.ts, b.jail, b.ip, b.ports, b.bantime_s, b.failures,
		coalesce((SELECT min(u.ts) FROM bans u WHERE u.event = 'unban' AND u.ip = b.ip AND u.jail = b.jail
			AND u.ts >= b.ts AND u.id > b.id), '')
		FROM bans b WHERE b.event = 'ban' AND b.ts >= ? AND (? = '' OR b.ip = ?) AND (? = '' OR b.jail = ?)
		ORDER BY b.ts DESC, b.id DESC LIMIT ?`,
		fmtTime(f.Since), f.IP, f.IP, f.Jail, f.Jail, f.Limit)
	if err != nil {
		return nil, err
	}
	var out []Ban
	for rows.Next() {
		var b Ban
		var ts, unban string
		var secs int64
		if err := rows.Scan(&b.ID, &ts, &b.Jail, &b.IP, &b.Ports, &secs, &b.Failures, &unban); err != nil {
			rows.Close()
			return nil, err
		}
		b.BannedAt, b.UnbannedAt, b.BanTime = parseTime(ts), parseTime(unban), time.Duration(secs)*time.Second
		out = append(out, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.banHits(&out[i], now); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) banHits(b *Ban, now time.Time) error {
	if err := s.db.QueryRow(`SELECT count(*) FROM hits WHERE client_ip = ? AND ts >= ? AND ts < ?`,
		b.IP, fmtTime(b.BannedAt.Add(-24*time.Hour)), fmtTime(b.BannedAt)).Scan(&b.HitsBefore); err != nil {
		return err
	}
	end := b.UnbannedAt
	if end.IsZero() {
		end = now
	}
	rows, err := s.db.Query(`SELECT host FROM hits WHERE client_ip = ? AND ts >= ? AND ts < ?`,
		b.IP, fmtTime(b.BannedAt.Add(BanGrace)), fmtTime(end))
	if err != nil {
		return err
	}
	defer rows.Close()
	covered := portSet(b.Ports)
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return err
		}
		if covered == nil || covered(hostPort(host)) {
			b.HitsDuring++
		}
	}
	return rows.Err()
}

// hostPort is the port a request arrived on, from its Host header. Without
// one it's the public HTTPS site.
func hostPort(host string) int {
	if _, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return 443
}

var namedPorts = map[string]int{"ssh": 22, "http": 80, "https": 443}

// portSet reads a fail2ban port setting ("80,443,8096", "ssh", "1000:2000").
// nil means every port.
func portSet(spec string) func(int) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" || spec == "0:65535" || spec == "1:65535" {
		return nil
	}
	type span struct{ lo, hi int }
	var spans []span
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, ":")
		a, errA := portNum(lo)
		b, errB := a, error(nil)
		if isRange {
			b, errB = portNum(hi)
		}
		if errA != nil || errB != nil {
			return nil // unreadable: count everything rather than hide a leak
		}
		spans = append(spans, span{a, b})
	}
	return func(p int) bool {
		for _, s := range spans {
			if p >= s.lo && p <= s.hi {
				return true
			}
		}
		return false
	}
}

func portNum(s string) (int, error) {
	if n, ok := namedPorts[strings.ToLower(s)]; ok {
		return n, nil
	}
	return strconv.Atoi(s)
}
