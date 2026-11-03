package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"dnscount/enrich"
)

// Roles: where an indicator was seen. Incoming roles are about who reaches
// us; outgoing ones about what the LAN reaches.
const (
	RoleHit      = 1 << iota // made a request to our sites
	RoleBan                  // banned by fail2ban
	RoleAlertSrc             // source of an IDS alert
	RoleTrip                 // tripped a breaker
	RoleLookup               // a domain LAN devices looked up
	RoleAnswer               // an address a lookup resolved to
	RoleConn                 // destination of a logged connection
	RoleAlertDst             // destination of an IDS alert
	RoleConnSrc              // source of a logged connection from outside (port forwards, WAN drops)

	RolesIn  = RoleHit | RoleBan | RoleAlertSrc | RoleTrip | RoleConnSrc
	RolesOut = RoleLookup | RoleAnswer | RoleConn | RoleAlertDst

	roleLAN = -1 // a dns_queries client: a LAN device
)

type indexSource struct {
	tbl, cols string
	roles     []int // one per column after the timestamp
}

var indexSources = []indexSource{
	{"hits", "ts, client_ip", []int{RoleHit}},
	{"bans", "ts, ip", []int{RoleBan}},
	{"ids_alerts", "ts, src_ip, dst_ip", []int{RoleAlertSrc, RoleAlertDst}},
	{"breaker_trips", "tripped_at, key", []int{RoleTrip}},
	{"dns_queries", "ts, client_ip, domain", []int{roleLAN, RoleLookup}},
	{"dns_replies", "ts, answer", []int{RoleAnswer}},
	{"connections", "ts, client_ip, dst_ip", []int{RoleConnSrc, RoleConn}},
}

type seenAgg struct {
	kind, first, last string
	roles             int
}

// IndexNew reads the rows added to src (the live database, read-only) since
// the last run into dst's indicator index, a batch at a time. It returns how
// many rows it read.
func IndexNew(src, dst *Store, batch int) (int, error) {
	if batch <= 0 {
		batch = 20000
	}
	total := 0
	for _, is := range indexSources {
		for {
			n, err := indexBatch(src, dst, is, batch)
			total += n
			if err != nil {
				return total, fmt.Errorf("index %s: %w", is.tbl, err)
			}
			if n < batch {
				break
			}
		}
	}
	return total, nil
}

func indexBatch(src, dst *Store, is indexSource, batch int) (int, error) {
	var last int64
	if err := dst.queryRow(`SELECT coalesce((SELECT last_id FROM cursors WHERE tbl = ?), 0)`, is.tbl).Scan(&last); err != nil {
		return 0, err
	}
	rows, err := src.query(`SELECT id, `+is.cols+` FROM `+is.tbl+` WHERE id > ? ORDER BY id LIMIT ?`, last, batch)
	if err != nil {
		return 0, err
	}
	inds, lan := map[string]*seenAgg{}, map[string]*seenAgg{}
	n := 0
	vals := make([]string, len(is.roles))
	dest := []any{&last, new(string)}
	for i := range vals {
		dest = append(dest, &vals[i])
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return 0, err
		}
		n++
		ts := *dest[1].(*string)
		for i, role := range is.roles {
			ind, kind := classify(vals[i], role)
			if ind == "" {
				continue
			}
			m := inds
			if role == roleLAN {
				m = lan
			}
			a := m[ind]
			if a == nil {
				a = &seenAgg{kind: kind, first: ts, last: ts}
				m[ind] = a
			}
			a.first, a.last = min(a.first, ts), max(a.last, ts)
			if role > 0 {
				a.roles |= role
			}
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	tx, err := dst.db.BeginTx(dst.c(), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for ind, a := range inds {
		if _, err := tx.Exec(`INSERT INTO indicators (indicator, kind, first_seen, last_seen, roles) VALUES (?,?,?,?,?)
			ON CONFLICT(indicator) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen),
			last_seen = max(last_seen, excluded.last_seen), roles = roles | excluded.roles`,
			ind, a.kind, a.first, a.last, a.roles); err != nil {
			return 0, err
		}
	}
	for ip, a := range lan {
		if _, err := tx.Exec(`INSERT INTO lan_clients (ip, first_seen, last_seen) VALUES (?,?,?)
			ON CONFLICT(ip) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen),
			last_seen = max(last_seen, excluded.last_seen)`, ip, a.first, a.last); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO cursors (tbl, last_id) VALUES (?, ?)
		ON CONFLICT(tbl) DO UPDATE SET last_id = excluded.last_id`, is.tbl, last); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// classify turns a column value into an indicator worth matching, or "".
func classify(v string, role int) (ind, kind string) {
	if role == roleLAN {
		if a, ok := enrich.PublicIP(v); ok || a.IsValid() {
			return a.String(), "ip"
		}
		return "", ""
	}
	if a, ok := enrich.PublicIP(v); ok {
		return a.String(), "ip"
	} else if a.IsValid() {
		return "", "" // a private address
	}
	if role == RoleLookup {
		if d, ok := enrich.PublicDomain(v); ok {
			return d, "domain"
		}
	}
	return "", ""
}

// Lists is everything the indicators get matched against.
type Lists struct {
	Lists []*enrich.List
	ASN   *enrich.ASNTable
}

// ReconcileStats says what one reconcile changed.
type ReconcileStats struct {
	Checked, Listed, Added, Removed int
}

const upsertMatch = `INSERT INTO enrichment (provider, indicator, kind, verdict, detail, matched_via, listed,
		first_listed, last_listed, removed_at, list_version) VALUES (?,?,?,?,?,?,1,?,?,'',?)
	ON CONFLICT(provider, indicator) DO UPDATE SET verdict = excluded.verdict, detail = excluded.detail,
		matched_via = excluded.matched_via, listed = 1, last_listed = excluded.last_listed, removed_at = '',
		list_version = excluded.list_version`

const markUnlisted = `UPDATE enrichment SET removed_at = CASE WHEN listed = 1 THEN ? ELSE removed_at END,
		listed = 0, list_version = ? WHERE provider = ? AND indicator = ?`

type windowInd struct {
	ind, kind string
	hasRow    bool
}

// Reconcile re-checks every indicator seen since `since` against one list's
// current contents: new matches are added, rows still matched are refreshed,
// and rows no longer matched are marked removed (kept, with removed_at).
// Rows for indicators older than the window keep the version they were
// checked against. s is the explorer's own database.
func (s *Store) Reconcile(l *enrich.List, since, now time.Time) (ReconcileStats, error) {
	var st ReconcileStats
	prov := l.Provider()
	rows, err := s.query(`SELECT i.indicator, i.kind, e.indicator IS NOT NULL FROM indicators i
		LEFT JOIN enrichment e ON e.provider = ? AND e.indicator = i.indicator
		WHERE i.last_seen >= ? AND i.indicator NOT IN (SELECT ip FROM lan_clients)`, prov, fmtTime(since))
	if err != nil {
		return st, err
	}
	var todo []windowInd
	for rows.Next() {
		var w windowInd
		if err := rows.Scan(&w.ind, &w.kind, &w.hasRow); err != nil {
			rows.Close()
			return st, err
		}
		todo = append(todo, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return st, err
	}
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	ts := fmtTime(now)
	for _, w := range todo {
		st.Checked++
		via, det, ok := l.Match(w.ind)
		switch {
		case ok:
			st.Listed++
			if !w.hasRow {
				st.Added++
			}
			if _, err := tx.Exec(upsertMatch, prov, w.ind, w.kind, l.Verdict, det, via, ts, ts, l.Version); err != nil {
				return st, err
			}
		case w.hasRow:
			res, err := tx.Exec(markUnlisted+` AND (listed = 1 OR list_version != ?)`, ts, l.Version, prov, w.ind, l.Version)
			if err != nil {
				return st, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				st.Removed++ // counts rows updated; most are newly removed
			}
		}
	}
	if _, err := tx.Exec(`INSERT INTO feed_versions (provider, version, loaded_at, entries) VALUES (?,?,?,?)
		ON CONFLICT(provider) DO UPDATE SET version = excluded.version, loaded_at = excluded.loaded_at,
		entries = excluded.entries`, prov, l.Version, ts, l.Entries); err != nil {
		return st, err
	}
	return st, tx.Commit()
}

// FeedVersion is the version of a list last reconciled, or "".
func (s *Store) FeedVersion(provider string) (string, error) {
	var v string
	err := s.queryRow(`SELECT version FROM feed_versions WHERE provider = ?`, provider).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// ReconcileASN re-looks-up every IP seen since `since`, recording owners
// that changed.
func (s *Store) ReconcileASN(t *enrich.ASNTable, since, now time.Time) (changed int, err error) {
	rows, err := s.query(`SELECT indicator FROM indicators WHERE kind = 'ip' AND last_seen >= ?`, fmtTime(since))
	if err != nil {
		return 0, err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return 0, err
		}
		ips = append(ips, ip)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, ip := range ips {
		c, err := setASN(tx, t, ip, now)
		if err != nil {
			return changed, err
		}
		if c {
			changed++
		}
	}
	if _, err := tx.Exec(`INSERT INTO feed_versions (provider, version, loaded_at, entries) VALUES ('asn:iptoasn',?,?,?)
		ON CONFLICT(provider) DO UPDATE SET version = excluded.version, loaded_at = excluded.loaded_at,
		entries = excluded.entries`, t.Version, fmtTime(now), t.Entries); err != nil {
		return changed, err
	}
	return changed, tx.Commit()
}

func setASN(tx *sql.Tx, t *enrich.ASNTable, ip string, now time.Time) (changed bool, err error) {
	a, _ := t.Lookup(ip)
	var oldASN int64
	var oldOwner string
	err = tx.QueryRow(`SELECT asn, as_owner FROM ip_asn WHERE ip = ?`, ip).Scan(&oldASN, &oldOwner)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return false, err
	case oldASN != int64(a.Number) || oldOwner != a.Owner:
		changed = true
		if _, err := tx.Exec(`INSERT INTO ip_asn_changes (ip, ts, old_asn, new_asn, old_owner, new_owner)
			VALUES (?,?,?,?,?,?)`, ip, fmtTime(now), oldASN, a.Number, oldOwner, a.Owner); err != nil {
			return false, err
		}
	}
	_, err = tx.Exec(`INSERT INTO ip_asn (ip, asn, as_owner, country, list_version, updated_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET asn = excluded.asn, as_owner = excluded.as_owner, country = excluded.country,
		list_version = excluded.list_version, updated_at = excluded.updated_at`,
		ip, a.Number, a.Owner, a.Country, t.Version, fmtTime(now))
	return changed, err
}

// matchOne checks one indicator against every list (and the ASN table, for
// IPs), adding, refreshing or removing its rows, and marks it checked.
func matchOne(tx *sql.Tx, ind, kind string, ls Lists, now time.Time) error {
	ts := fmtTime(now)
	for _, l := range ls.Lists {
		if via, det, ok := l.Match(ind); ok {
			if _, err := tx.Exec(upsertMatch, l.Provider(), ind, kind, l.Verdict, det, via, ts, ts, l.Version); err != nil {
				return err
			}
		} else if _, err := tx.Exec(markUnlisted, ts, l.Version, l.Provider(), ind); err != nil {
			return err
		}
	}
	if kind == "ip" && ls.ASN != nil {
		if _, err := setASN(tx, ls.ASN, ind, now); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`UPDATE indicators SET checked_at = ? WHERE indicator = ?`, ts, ind)
	return err
}

// MatchNew matches every indicator not yet checked against all lists. It
// returns how many it checked.
func (s *Store) MatchNew(ls Lists, now time.Time) (int, error) {
	total := 0
	for {
		rows, err := s.query(`SELECT indicator, kind FROM indicators WHERE checked_at = ''
			AND indicator NOT IN (SELECT ip FROM lan_clients) LIMIT 5000`)
		if err != nil {
			return total, err
		}
		var todo []windowInd
		for rows.Next() {
			var w windowInd
			if err := rows.Scan(&w.ind, &w.kind); err != nil {
				rows.Close()
				return total, err
			}
			todo = append(todo, w)
		}
		rows.Close()
		if err := rows.Err(); err != nil || len(todo) == 0 {
			return total, err
		}
		tx, err := s.db.BeginTx(s.c(), nil)
		if err != nil {
			return total, err
		}
		for _, w := range todo {
			if err := matchOne(tx, w.ind, w.kind, ls, now); err != nil {
				tx.Rollback()
				return total, err
			}
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}
		total += len(todo)
	}
}

// Rematch brings one indicator up to date with the current lists, so a
// profile page is never stale even for indicators outside the window. It's a
// no-op for indicators the index has never seen.
func (s *Store) Rematch(ind string, ls Lists, now time.Time) error {
	var kind string
	err := s.queryRow(`SELECT kind FROM indicators WHERE indicator = ?`, ind).Scan(&kind)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := matchOne(tx, ind, kind, ls, now); err != nil {
		return err
	}
	return tx.Commit()
}

// OutdatedRows counts, per provider, rows for indicators seen since `since`
// that were last checked against a version other than the current one.
// After each reconcile this should be 0.
func (s *Store) OutdatedRows(since time.Time) (map[string]int64, error) {
	rows, err := s.query(`SELECT e.provider, count(*) FROM enrichment e
		JOIN feed_versions v ON v.provider = e.provider
		JOIN indicators i ON i.indicator = e.indicator
		WHERE e.list_version != v.version AND i.last_seen >= ? GROUP BY e.provider`, fmtTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var p string
		var n int64
		if err := rows.Scan(&p, &n); err != nil {
			return nil, err
		}
		out[p] = n
	}
	return out, rows.Err()
}

// FeedMatch is an indicator's row for one list.
type FeedMatch struct {
	Provider    string    `json:"provider"`
	Verdict     string    `json:"verdict"`
	Detail      string    `json:"detail,omitempty"`
	Via         string    `json:"matched_via,omitempty"`
	Listed      bool      `json:"listed"`
	FirstListed time.Time `json:"first_listed"`
	LastListed  time.Time `json:"last_listed"`
	RemovedAt   time.Time `json:"removed_at,omitzero"`
}

// Intel is what's known about one indicator.
type Intel struct {
	ASN     uint32 `json:"asn,omitempty"`
	Owner   string `json:"as_owner,omitempty"`
	Country string `json:"country,omitempty"`
	// Verdict is the worst verdict among the lists it's on now, or
	// "reserved" for a reserved special-purpose address or name, whatever
	// lists it's on: not a real host, so never flagged.
	Verdict string `json:"verdict,omitempty"`
	// Special is set for special-purpose addresses and names (RFC 6890).
	Special *enrich.Special `json:"special,omitempty"`
	// Feeds are the lists it's on now.
	Feeds []string `json:"feeds,omitempty"`
	// Matches has every row, including lists it has dropped off. Only set
	// for profiles.
	Matches []FeedMatch `json:"matches,omitempty"`
}

// Flagged says whether the verdict is worth attention (not just info).
func (i *Intel) Flagged() bool { return i != nil && enrich.VerdictRank(i.Verdict) >= 2 }

// Intel looks up indicators in the attached enrich database. With history,
// lists an indicator dropped off are included in Matches.
func (s *Store) Intel(inds []string, history bool) (map[string]*Intel, error) {
	out := map[string]*Intel{}
	get := func(k string) *Intel {
		if out[k] == nil {
			out[k] = &Intel{}
		}
		return out[k]
	}
	for start := 0; start < len(inds); start += 400 {
		chunk := inds[start:min(start+400, len(inds))]
		args := make([]any, len(chunk))
		for i, v := range chunk {
			args[i] = v
		}
		in := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		listed := ` AND listed = 1`
		if history {
			listed = ``
		}
		rows, err := s.query(`SELECT indicator, provider, verdict, detail, matched_via, listed, first_listed,
			last_listed, removed_at FROM enrich.enrichment WHERE indicator IN (`+in+`)`+listed+`
			ORDER BY indicator, listed DESC, provider`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ind, first, last, removed string
			var m FeedMatch
			if err := rows.Scan(&ind, &m.Provider, &m.Verdict, &m.Detail, &m.Via, &m.Listed, &first, &last, &removed); err != nil {
				rows.Close()
				return nil, err
			}
			m.FirstListed, m.LastListed, m.RemovedAt = parseTime(first), parseTime(last), parseTime(removed)
			in := get(ind)
			if m.Listed {
				in.Feeds = append(in.Feeds, m.Provider)
				if !enrich.Reserved(ind) && enrich.VerdictRank(m.Verdict) > enrich.VerdictRank(in.Verdict) {
					in.Verdict = m.Verdict
				}
			}
			if history {
				in.Matches = append(in.Matches, m)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows, err = s.query(`SELECT ip, asn, as_owner, country FROM enrich.ip_asn WHERE ip IN (`+in+`) AND asn > 0`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			var a Intel
			if err := rows.Scan(&ip, &a.ASN, &a.Owner, &a.Country); err != nil {
				rows.Close()
				return nil, err
			}
			in := get(ip)
			in.ASN, in.Owner, in.Country = a.ASN, a.Owner, a.Country
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	// Special-purpose addresses and names get their context, listed or not.
	for _, ind := range inds {
		if sp, ok := enrich.SpecialFor(ind); ok {
			in := get(ind)
			in.Special = &sp
			if sp.Reserved {
				in.Verdict = enrich.VerdictReserved
			}
		}
	}
	return out, nil
}
