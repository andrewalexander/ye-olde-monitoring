package store

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefenseEvent is one thing done about an address: an IDS block, a ban, a
// breaker trip, a refused login or a firewall drop. Warn marks one that
// didn't hold (a ban that leaked) or a detection nothing acted on (an IDS
// alert let through).
type DefenseEvent struct {
	TS   time.Time `json:"ts"`
	Kind string    `json:"kind"`           // ids | ban | trip | login | fw
	Warn string    `json:"warn,omitempty"` // leak | allowed
	IP   string    `json:"ip"`             // the address acted on
	To   string    `json:"to,omitempty"`   // where it was going (ids, fw)
	Port int       `json:"port,omitempty"`
	What string    `json:"what"`         // one line about it
	ID   int64     `json:"id,omitempty"` // a ban's or trip's id, for its page
}

// Defense kinds a DefenseFilter selects. "allowed" is IDS alerts let
// through (kind ids, warn allowed).
const (
	DefenseIDS     = "ids"
	DefenseAllowed = "allowed"
	DefenseBan     = "ban"
	DefenseTrip    = "trip"
	DefenseLogin   = "login"
	DefenseFW      = "fw"
)

// DefenseFilter selects defense events. No kinds means every kind except
// firewall drops, which run to tens of thousands a day and would bury the
// rest; "all" adds them.
type DefenseFilter struct {
	Since time.Time
	IP    string
	Kinds []string
	Limit int
}

func (f DefenseFilter) kinds() (map[string]bool, error) {
	want := map[string]bool{}
	if len(f.Kinds) == 0 {
		f.Kinds = []string{DefenseIDS, DefenseAllowed, DefenseBan, DefenseTrip, DefenseLogin}
	}
	for _, k := range f.Kinds {
		switch k = strings.TrimSpace(k); k {
		case "all":
			for _, k := range []string{DefenseIDS, DefenseAllowed, DefenseBan, DefenseTrip, DefenseLogin, DefenseFW} {
				want[k] = true
			}
		case DefenseIDS, DefenseAllowed, DefenseBan, DefenseTrip, DefenseLogin, DefenseFW:
			want[k] = true
		case "":
		default:
			return nil, BadQueryError("kind must be ids, allowed, ban, trip, login, fw or all, not " + k)
		}
	}
	return want, nil
}

// Firewall drops newest first over a window, all addresses or one.
const (
	defenseDrops = `SELECT id, ts, client_ip, dst_ip, dst_port, proto, action, rule, source
		FROM connections INDEXED BY connections_dropped WHERE action IN ('drop', 'reject') AND ts >= ?
		ORDER BY ts DESC LIMIT ?`
	defenseDropsFor = `SELECT id, ts, client_ip, dst_ip, dst_port, proto, action, rule, source
		FROM connections INDEXED BY connections_client_ip WHERE action IN ('drop', 'reject') AND ts >= ? AND client_ip = ?
		ORDER BY ts DESC LIMIT ?`
)

// Defenses lists defense events newest first. Each source is read newest
// first up to the limit and the results merged, so none is read past a page.
func (s *Store) Defenses(f DefenseFilter, now time.Time) ([]DefenseEvent, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	want, err := f.kinds()
	if err != nil {
		return nil, err
	}
	var out []DefenseEvent

	if want[DefenseIDS] || want[DefenseAllowed] {
		action := ""
		if !want[DefenseIDS] {
			action = "allowed"
		} else if !want[DefenseAllowed] {
			action = "blocked"
		}
		alerts, err := s.Alerts(AlertFilter{Since: f.Since, IP: f.IP, Action: action, Limit: f.Limit})
		if err != nil {
			return nil, err
		}
		for _, a := range alerts {
			if f.IP != "" && a.SrcIP != f.IP {
				continue // Alerts matches either end; the address acted on is the source
			}
			e := DefenseEvent{TS: a.TS, Kind: DefenseIDS, IP: a.SrcIP, To: a.DstIP, Port: a.DstPort, What: a.Signature}
			if extra := joinNonEmpty(a.Category, a.Direction); extra != "" {
				e.What += " (" + extra + ")"
			}
			if a.Action == "allowed" {
				e.Warn = DefenseAllowed
			}
			out = append(out, e)
		}
	}

	if want[DefenseBan] {
		bans, err := s.Bans(BanFilter{Since: f.Since, IP: f.IP, Limit: f.Limit}, now)
		if err != nil {
			return nil, err
		}
		for _, b := range bans {
			e := DefenseEvent{TS: b.BannedAt, Kind: DefenseBan, IP: b.IP, ID: b.ID,
				What: fmt.Sprintf("%s: %d matches", b.Jail, b.Failures)}
			if b.BanTime > 0 {
				e.What += ", for " + shortDur(b.BanTime)
			}
			if b.Restored {
				e.What += ", restored after a restart"
			}
			if b.HitsDuring > 0 {
				e.Warn = "leak"
				e.What += fmt.Sprintf(", %d got through", b.HitsDuring)
			}
			out = append(out, e)
		}
	}

	if want[DefenseTrip] {
		trips, err := s.Trips(TripFilter{Since: f.Since, Key: f.IP, Limit: f.Limit})
		if err != nil {
			return nil, err
		}
		for _, t := range trips {
			out = append(out, DefenseEvent{TS: t.TrippedAt, Kind: DefenseTrip, IP: t.Key, ID: t.ID,
				What: t.Breaker + ": " + t.Reason})
		}
	}

	if want[DefenseLogin] {
		logins, err := s.AuthFailuresBetween(f.IP, f.Since, time.Time{}, f.Limit)
		if err != nil {
			return nil, err
		}
		for _, l := range logins {
			out = append(out, DefenseEvent{TS: l.TS, Kind: DefenseLogin, IP: l.IP,
				What: fmt.Sprintf("%s refused %q", l.Source, l.User)})
		}
	}

	if want[DefenseFW] {
		q, args := defenseDropsFor, []any{fmtTime(f.Since), f.IP, f.Limit}
		if f.IP == "" {
			// The explorer opens the database read-only, so the index
			// comes from the writer's schema.
			if err := s.needDroppedIndex(); err != nil {
				return nil, err
			}
			q, args = defenseDrops, []any{fmtTime(f.Since), f.Limit}
		}
		rows, err := s.query(q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var ts, ip, dst, proto, action, rule, source string
			var port int
			if err := rows.Scan(&id, &ts, &ip, &dst, &port, &proto, &action, &rule, &source); err != nil {
				rows.Close()
				return nil, err
			}
			e := DefenseEvent{TS: parseTime(ts), Kind: DefenseFW, IP: ip, To: dst, Port: port}
			if source == "host-fw" {
				e.What = "rejected by this host while banned (" + rule + ")"
			} else {
				e.What = action + " by " + joinNonEmpty(rule, proto)
			}
			out = append(out, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	slices.SortStableFunc(out, func(a, b DefenseEvent) int {
		return cmp.Or(b.TS.Compare(a.TS), cmp.Compare(b.ID, a.ID))
	})
	return out[:min(len(out), f.Limit)], nil
}

// needDroppedIndex says, as a BadQueryError, that the connections_dropped
// index isn't there yet: the explorer opens the database read-only, so it
// comes from dnscount syslog's schema when that next starts.
func (s *Store) needDroppedIndex() error {
	var n int
	if err := s.queryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'connections_dropped'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return BadQueryError("listing firewall drops needs the connections_dropped index, which dnscount syslog creates when it next starts")
	}
	return nil
}

func joinNonEmpty(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), ", ")
}

// shortDur is a duration without its zero tail: 1h, 1h30m, 10m.
func shortDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
