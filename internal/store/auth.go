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
	rows, err := s.query(`SELECT ts, source, ip, user FROM auth_failures WHERE ip = ? AND ts >= ?
		ORDER BY ts DESC, id DESC LIMIT ?`, ip, fmtTime(since), limit)
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
