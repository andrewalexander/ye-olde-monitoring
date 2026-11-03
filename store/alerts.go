package store

import (
	"time"
)

// Alert is one row of ids_alerts, plus how many requests its source made to
// our sites over the same period.
type Alert struct {
	ID          int64     `json:"id"`
	TS          time.Time `json:"ts"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     int       `json:"src_port"`
	DstIP       string    `json:"dst_ip"`
	DstPort     int       `json:"dst_port"`
	Proto       string    `json:"proto"`
	Action      string    `json:"action"`
	Signature   string    `json:"signature"`
	SignatureID int64     `json:"signature_id"`
	Category    string    `json:"category"`
	Severity    int       `json:"severity"`
	Source      string    `json:"source"`
	SrcHits     int64     `json:"src_hits"`
}

// AlertFilter selects alerts; empty fields match everything. IP matches
// either end.
type AlertFilter struct {
	Since  time.Time
	IP     string
	Action string // allowed | blocked
	Limit  int
}

const alertWhere = `ts >= ? AND (? = '' OR src_ip = ? OR dst_ip = ?) AND (? = '' OR action = ?)`

func (f AlertFilter) args() []any {
	return []any{fmtTime(f.Since), f.IP, f.IP, f.IP, f.Action, f.Action}
}

// Alerts lists alerts newest first.
func (s *Store) Alerts(f AlertFilter) ([]Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := s.db.Query(`SELECT a.id, a.ts, a.src_ip, a.src_port, a.dst_ip, a.dst_port, a.proto, a.action,
		a.signature, a.signature_id, a.category, a.severity, a.source,
		(SELECT count(*) FROM hits h WHERE h.client_ip = a.src_ip AND h.ts >= ?)
		FROM ids_alerts a WHERE `+alertWhere+` ORDER BY a.ts DESC, a.id DESC LIMIT ?`,
		append(append([]any{fmtTime(f.Since)}, f.args()...), f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var ts string
		if err := rows.Scan(&a.ID, &ts, &a.SrcIP, &a.SrcPort, &a.DstIP, &a.DstPort, &a.Proto, &a.Action,
			&a.Signature, &a.SignatureID, &a.Category, &a.Severity, &a.Source, &a.SrcHits); err != nil {
			return nil, err
		}
		a.TS = parseTime(ts)
		out = append(out, a)
	}
	return out, rows.Err()
}

var alertColumns = map[string]string{
	"signature": "signature", "src": "src_ip", "dst": "dst_ip", "category": "category", "action": "action",
}

// TopAlerts counts alerts grouped by one column (signature, src, dst,
// category or action), most common first.
func (s *Store) TopAlerts(by string, f AlertFilter) ([]KV, error) {
	col, ok := alertColumns[by]
	if !ok {
		return nil, BadQueryError("alerts can be grouped by signature, src, dst, category or action, not " + by)
	}
	if f.Limit <= 0 {
		f.Limit = 25
	}
	rows, err := s.db.Query(`SELECT `+col+`, count(*), min(ts) FROM ids_alerts WHERE `+alertWhere+`
		GROUP BY `+col+` ORDER BY count(*) DESC, `+col+` LIMIT ?`, append(f.args(), f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KV
	for rows.Next() {
		var kv KV
		var first string
		if err := rows.Scan(&kv.Key, &kv.Count, &first); err != nil {
			return nil, err
		}
		kv.First = parseTime(first)
		out = append(out, kv)
	}
	return out, rows.Err()
}
