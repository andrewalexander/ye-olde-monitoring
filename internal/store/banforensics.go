package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// insertBanFound writes a ban's stub forensics row: the times of the lines
// fail2ban matched. fail2ban's journal is read again on every start, so a
// ban recorded before its found times were (or before this table existed)
// gets them now, and its detail is redone with them.
const insertBanFound = `INSERT INTO ban_forensics (ban_id, found_json)
	SELECT id, ? FROM bans WHERE line_hash = ?
	ON CONFLICT(ban_id) DO UPDATE SET found_json = excluded.found_json, detail_json = '', during_done = 0
	WHERE ban_forensics.found_json = '[]' AND excluded.found_json != '[]'`

func foundJSON(ts []time.Time) string {
	if len(ts) == 0 {
		return "[]"
	}
	s := make([]string, len(ts))
	for i, t := range ts {
		s[i] = fmtTime(t)
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// PendingBan is a ban (or ignored event) whose forensics aren't recorded yet.
type PendingBan struct {
	ID    int64
	TS    time.Time
	Event string // ban | ignored
	Jail  string
	IP    string
	Ports string
	Found []time.Time
	// RestoredOf is the ban this one continues when fail2ban re-applied it
	// after a restart (see Ban.Restored); 0 otherwise.
	RestoredOf int64
}

// BansNeedingForensics lists bans and ignored events from before `before`
// that have no forensics detail yet, oldest first.
func (s *Store) BansNeedingForensics(before time.Time, limit int) ([]PendingBan, error) {
	rows, err := s.query(`SELECT b.id, b.ts, b.event, b.jail, b.ip, b.ports, coalesce(f.found_json, '[]'),
		coalesce((SELECT max(u.ts) FROM bans u WHERE u.event = 'unban' AND u.ip = b.ip AND u.jail = b.jail
			AND u.ts <= b.ts AND u.id < b.id), '')
		FROM bans b LEFT JOIN ban_forensics f ON f.ban_id = b.id
		WHERE b.event IN ('ban', 'ignored') AND b.ts < ? AND coalesce(f.detail_json, '') = ''
		ORDER BY b.ts, b.id LIMIT ?`, fmtTime(before), limit)
	if err != nil {
		return nil, err
	}
	var out []PendingBan
	for rows.Next() {
		var p PendingBan
		var ts, found, prevUnban string
		if err := rows.Scan(&p.ID, &ts, &p.Event, &p.Jail, &p.IP, &p.Ports, &found, &prevUnban); err != nil {
			rows.Close()
			return nil, err
		}
		p.TS = parseTime(ts)
		var fs []string
		json.Unmarshal([]byte(found), &fs)
		for _, f := range fs {
			p.Found = append(p.Found, parseTime(f))
		}
		if p.Event == "ban" && prevUnban != "" && p.TS.Sub(parseTime(prevUnban)) <= RestoreGap {
			p.RestoredOf = -1 // looked up below, once rows is closed
		}
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].RestoredOf == 0 {
			continue
		}
		// The ban before the unban that the restart logged.
		if err := s.queryRow(`SELECT coalesce(max(id), 0) FROM bans WHERE event = 'ban' AND ip = ? AND jail = ?
			AND id < ? AND ts < ?`, out[i].IP, out[i].Jail, out[i].ID, fmtTime(out[i].TS.Add(-time.Nanosecond))).
			Scan(&out[i].RestoredOf); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SetBanDetail stores a ban's forensics detail.
func (s *Store) SetBanDetail(id int64, detail json.RawMessage, at time.Time, backfilled bool) error {
	_, err := s.exec(`INSERT INTO ban_forensics (ban_id, detail_json, recorded_at, backfilled) VALUES (?,?,?,?)
		ON CONFLICT(ban_id) DO UPDATE SET detail_json = excluded.detail_json,
			recorded_at = excluded.recorded_at, backfilled = excluded.backfilled`,
		id, string(detail), fmtTime(at), backfilled)
	return err
}

// BansNeedingDuring lists ended bans whose detail is recorded but not yet
// what happened while they were in force, oldest first.
func (s *Store) BansNeedingDuring(limit int) ([]Ban, error) {
	rows, err := s.query(`SELECT id, ts, jail, ip, ports, unban FROM (
		SELECT b.id, b.ts, b.jail, b.ip, b.ports,
			(SELECT min(u.ts) FROM bans u WHERE u.event = 'unban' AND u.ip = b.ip AND u.jail = b.jail
				AND u.ts >= b.ts AND u.id > b.id) AS unban
		FROM bans b JOIN ban_forensics f ON f.ban_id = b.id
		WHERE b.event = 'ban' AND f.during_done = 0 AND f.detail_json != '')
		WHERE unban IS NOT NULL ORDER BY ts, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var ts, unban string
		if err := rows.Scan(&b.ID, &ts, &b.Jail, &b.IP, &b.Ports, &unban); err != nil {
			return nil, err
		}
		b.BannedAt, b.UnbannedAt = parseTime(ts), parseTime(unban)
		out = append(out, b)
	}
	return out, rows.Err()
}

// SetBanDuring adds what happened while a ban was in force to its detail.
func (s *Store) SetBanDuring(id int64, during json.RawMessage) error {
	_, err := s.exec(`UPDATE ban_forensics SET detail_json = json_set(detail_json, '$.during', json(?)),
		during_done = 1 WHERE ban_id = ?`, string(during), id)
	return err
}

// ConnSample is one firewall line about an address.
type ConnSample struct {
	TS      time.Time `json:"ts"`
	DstIP   string    `json:"dst_ip"`
	DstPort int       `json:"dst_port"`
	Proto   string    `json:"proto"`
	Action  string    `json:"action"`
	Rule    string    `json:"rule"`
	Source  string    `json:"source"`
}

// BlockedTraffic is what an address sent while banned: this host's
// firewall lines for the ban's rule, and the router's.
type BlockedTraffic struct {
	// Blocked is how many packets this host logged rejecting (at most
	// 12 a minute are logged, so a flood shows as about that rate).
	Blocked int64 `json:"blocked"`
	// Ports is Blocked per destination port.
	Ports map[int]int64 `json:"ports,omitempty"`
	// Samples are the first few, like a trip's late samples.
	Samples []ConnSample `json:"late_samples,omitempty"`
	// RouterSeen is the router's firewall lines from it in the same time.
	RouterSeen int64 `json:"router_seen"`
}

// BlockedTrafficFor is what ip sent in [from, to): rule is the host
// firewall's log prefix for the jail (f2b-<jail>).
func (s *Store) BlockedTrafficFor(ip, rule string, from, to time.Time, samples int) (BlockedTraffic, error) {
	t := BlockedTraffic{Ports: map[int]int64{}}
	rows, err := s.query(`SELECT dst_port, count(*) FROM connections WHERE client_ip = ? AND rule = ?
		AND ts >= ? AND ts < ? GROUP BY dst_port`, ip, rule, fmtTime(from), fmtTime(to))
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var port int
		var n int64
		if err := rows.Scan(&port, &n); err != nil {
			rows.Close()
			return t, err
		}
		t.Ports[port] = n
		t.Blocked += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, err
	}
	rows, err = s.query(`SELECT ts, dst_ip, dst_port, proto, action, rule, source FROM connections
		WHERE client_ip = ? AND rule = ? AND ts >= ? AND ts < ? ORDER BY ts, id LIMIT ?`,
		ip, rule, fmtTime(from), fmtTime(to), samples)
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var c ConnSample
		var ts string
		if err := rows.Scan(&ts, &c.DstIP, &c.DstPort, &c.Proto, &c.Action, &c.Rule, &c.Source); err != nil {
			rows.Close()
			return t, err
		}
		c.TS = parseTime(ts)
		t.Samples = append(t.Samples, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return t, err
	}
	err = s.queryRow(`SELECT count(*) FROM connections WHERE client_ip = ? AND source != 'host-fw'
		AND ts >= ? AND ts < ?`, ip, fmtTime(from), fmtTime(to)).Scan(&t.RouterSeen)
	return t, err
}

// LeakedHits counts b's requests that reached a site on a port it blocks
// while it was in force (Ban.HitsDuring).
func (s *Store) LeakedHits(b Ban) (int64, error) {
	err := s.banHits(&b, b.UnbannedAt)
	return b.HitsDuring, err
}

// HitTimes is when ip's hits in [from, to) arrived, oldest first.
func (s *Store) HitTimes(ip string, from, to time.Time) ([]time.Time, error) {
	rows, err := s.query(`SELECT ts FROM hits WHERE client_ip = ? AND ts >= ? AND ts < ? ORDER BY ts`,
		ip, fmtTime(from), fmtTime(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		out = append(out, parseTime(ts))
	}
	return out, rows.Err()
}

// BanDetail is a ban's stored forensics, nil if none were recorded.
func (s *Store) BanDetail(id int64) (json.RawMessage, error) {
	var d string
	err := s.queryRow(`SELECT detail_json FROM ban_forensics WHERE ban_id = ?`, id).Scan(&d)
	if err == sql.ErrNoRows || (err == nil && d == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(d), nil
}
