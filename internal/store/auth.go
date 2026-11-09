package store

import "time"

// AuthFailure is one refused login.
type AuthFailure struct {
	TS     time.Time `json:"ts"`
	Source string    `json:"source"`
	IP     string    `json:"ip"`
	User   string    `json:"user"`
}

// AuthFailures lists ip's refused logins since `since`, newest first.
func (s *Store) AuthFailures(ip string, since time.Time, limit int) ([]AuthFailure, error) {
	return s.AuthFailuresBetween(ip, since, time.Time{}, limit)
}

// Refused logins in a window, newest first: one address's, or everyone's.
const (
	authFailuresFor = `SELECT ts, source, ip, user FROM auth_failures INDEXED BY auth_failures_ip
		WHERE ip = ? AND ts >= ? AND ts < ? ORDER BY ts DESC, id DESC LIMIT ?`
	authFailuresAll = `SELECT ts, source, ip, user FROM auth_failures INDEXED BY auth_failures_ts
		WHERE ts >= ? AND ts < ? ORDER BY ts DESC LIMIT ?`
)

// AuthFailuresBetween lists ip's refused logins in [since, until), newest
// first; everyone's if ip is "". A zero until has no upper bound.
func (s *Store) AuthFailuresBetween(ip string, since, until time.Time, limit int) ([]AuthFailure, error) {
	q, args := authFailuresFor, []any{ip, fmtTime(since), upper(until), limit}
	if ip == "" {
		q, args = authFailuresAll, args[1:]
	}
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthFailure{}
	for rows.Next() {
		var a AuthFailure
		var ts string
		if err := rows.Scan(&ts, &a.Source, &a.IP, &a.User); err != nil {
			return nil, err
		}
		a.TS = parseTime(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}
