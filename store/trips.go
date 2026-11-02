package store

import (
	"encoding/json"
	"time"
)

// Trip is one row of breaker_trips.
type Trip struct {
	ID            int64           `json:"id"`
	TrippedAt     time.Time       `json:"tripped_at"`
	CooldownUntil time.Time       `json:"cooldown_until"`
	EndedAt       time.Time       `json:"ended_at,omitzero"`
	Breaker       string          `json:"breaker"`
	Key           string          `json:"key"`
	Reason        string          `json:"reason"`
	WindowEvents  int             `json:"window_events"`
	WindowBad     int             `json:"window_bad"`
	Suppressed    int             `json:"suppressed_during_cooldown"`
	FirstSeen     time.Time       `json:"first_seen_in_window"`
	Detail        json.RawMessage `json:"detail,omitempty"`
}

func (s *Store) InsertTrip(t Trip) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO breaker_trips (tripped_at, cooldown_until, breaker, key, reason,
		window_events, window_bad, suppressed_during_cooldown, first_seen_in_window, detail_json)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, fmtTime(t.TrippedAt), fmtTime(t.CooldownUntil), t.Breaker, t.Key, t.Reason,
		t.WindowEvents, t.WindowBad, t.Suppressed, fmtTime(t.FirstSeen), string(t.Detail))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EndTrip closes a trip once its cooldown is over, recording how much was
// suppressed and any extra samples collected during cooldown.
func (s *Store) EndTrip(id int64, ended time.Time, suppressed int, lateSamples json.RawMessage) error {
	if len(lateSamples) == 0 {
		lateSamples = json.RawMessage("[]")
	}
	_, err := s.db.Exec(`UPDATE breaker_trips SET ended_at = ?, suppressed_during_cooldown = ?,
		detail_json = json_set(detail_json, '$.late_samples', json(?)) WHERE id = ?`,
		fmtTime(ended), suppressed, string(lateSamples), id)
	return err
}

// TripFilter selects trips; empty fields match everything.
type TripFilter struct {
	Since   time.Time
	Key     string
	Breaker string
	Limit   int
}

// Trips lists trips newest first, without the detail blob.
func (s *Store) Trips(f TripFilter) ([]Trip, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := s.db.Query(`SELECT id, tripped_at, cooldown_until, ended_at, breaker, key, reason,
		window_events, window_bad, suppressed_during_cooldown, first_seen_in_window, '' FROM breaker_trips
		WHERE tripped_at >= ? AND (? = '' OR key = ?) AND (? = '' OR breaker = ?)
		ORDER BY tripped_at DESC, id DESC LIMIT ?`,
		fmtTime(f.Since), f.Key, f.Key, f.Breaker, f.Breaker, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Trip
	for rows.Next() {
		t, err := scanTrip(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Trip returns one trip with its full detail.
func (s *Store) Trip(id int64) (Trip, error) {
	return scanTrip(s.db.QueryRow(`SELECT id, tripped_at, cooldown_until, ended_at, breaker, key, reason,
		window_events, window_bad, suppressed_during_cooldown, first_seen_in_window, detail_json
		FROM breaker_trips WHERE id = ?`, id))
}

func (s *Store) TripCount(key string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT count(*) FROM breaker_trips WHERE key = ?`, key).Scan(&n)
	return n, err
}

type scanner interface{ Scan(...any) error }

func scanTrip(r scanner) (Trip, error) {
	var t Trip
	var tripped, cool, ended, first, detail string
	err := r.Scan(&t.ID, &tripped, &cool, &ended, &t.Breaker, &t.Key, &t.Reason,
		&t.WindowEvents, &t.WindowBad, &t.Suppressed, &first, &detail)
	t.TrippedAt, t.CooldownUntil, t.EndedAt, t.FirstSeen = parseTime(tripped), parseTime(cool), parseTime(ended), parseTime(first)
	if detail != "" {
		t.Detail = json.RawMessage(detail)
	}
	return t, err
}
