package store

import (
	"fmt"
	"net/netip"
	"time"
)

// Check runs data-sanity checks and returns one line per problem found.
// An empty result means the database looks sane.
func (s *Store) Check(now time.Time) ([]string, error) {
	var problems []string
	future := fmtTime(now.Add(24 * time.Hour))
	past := fmtTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	counts := []struct{ what, q string }{
		{"hits with empty client_ip", `SELECT count(*) FROM hits WHERE client_ip = ''`},
		{"hits with status outside 100-599", `SELECT count(*) FROM hits WHERE status != 0 AND (status < 100 OR status > 599)`},
		{"dns_queries with empty domain or client", `SELECT count(*) FROM dns_queries WHERE domain = '' OR client_ip = ''`},
		{"dns_queries with uppercase or trailing-dot domain", `SELECT count(*) FROM dns_queries WHERE domain != lower(domain) OR domain LIKE '%.'`},
		{"dns_replies with empty domain", `SELECT count(*) FROM dns_replies WHERE domain = ''`},
		{"connections with empty client_ip or dst_ip", `SELECT count(*) FROM connections WHERE client_ip = '' OR dst_ip = ''`},
		{"counters higher than the hits recorded for their site", `SELECT count(*) FROM counters c
			WHERE c.count > (SELECT count(*) FROM hits h WHERE h.site = c.site)`},
	}
	for _, table := range []string{"hits", "dns_queries", "dns_replies", "connections", "ids_alerts", "bans"} {
		counts = append(counts,
			struct{ what, q string }{table + " timestamped in the future", `SELECT count(*) FROM ` + table + ` WHERE ts > '` + future + `'`},
			struct{ what, q string }{table + " timestamped before 2000", `SELECT count(*) FROM ` + table + ` WHERE ts < '` + past + `'`})
	}
	for _, c := range counts {
		var n int
		if err := s.db.QueryRow(c.q).Scan(&n); err != nil {
			return nil, fmt.Errorf("%s: %w", c.what, err)
		}
		if n > 0 {
			problems = append(problems, fmt.Sprintf("%d %s", n, c.what))
		}
	}
	for _, c := range []struct{ table, col string }{
		{"hits", "client_ip"}, {"dns_queries", "client_ip"}, {"connections", "client_ip"}, {"connections", "dst_ip"},
		{"ids_alerts", "src_ip"}, {"ids_alerts", "dst_ip"}, {"bans", "ip"},
	} {
		n, err := s.countBadIPs(c.table, c.col)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			problems = append(problems, fmt.Sprintf("%d %s with invalid %s", n, c.table, c.col))
		}
	}
	return problems, nil
}

func (s *Store) countBadIPs(table, col string) (int, error) {
	rows, err := s.db.Query(`SELECT DISTINCT ` + col + ` FROM ` + table)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return 0, err
		}
		if _, err := netip.ParseAddr(ip); err != nil && ip != "" {
			n++
		}
	}
	return n, rows.Err()
}
