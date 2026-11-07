package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/enrich"
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
	RoleConn                 // destination of a logged connection from a LAN device (LAN → internet)
	RoleAlertDst             // destination of an IDS alert
	RoleConnSrc              // source of a logged connection from outside (port forwards, WAN drops)
	RoleAuthFail             // an app refused its login (new roles go last: the bits are stored)

	RolesIn  = RoleHit | RoleBan | RoleAlertSrc | RoleTrip | RoleConnSrc | RoleAuthFail
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
	{"auth_failures", "ts, ip", []int{RoleAuthFail}},
	{"dns_queries", "ts, client_ip, domain", []int{roleLAN, RoleLookup}},
	{"dns_replies", "ts, answer", []int{RoleAnswer}},
	// A destination counts only when a LAN device was the source: for traffic
	// coming at us (WAN drops, port forwards) it's our own address.
	{"connections", "ts, client_ip, dst_ip", []int{RoleConnSrc, RoleConn}},
	{"lan_sightings", "ts, ip", []int{roleLAN}}, // DHCP, UniFi and neighbour-table sightings are LAN devices
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
	if err := dst.resetIndexIfOld(); err != nil {
		return 0, err
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
			if role == RoleConn && !privateAddr(vals[0]) {
				continue
			}
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
		d, ok := enrich.PublicDomain(v)
		if _, special := enrich.SpecialDomain(d); ok || special {
			return d, "domain" // special-use names like ipv4only.arpa are kept for context
		}
	}
	return "", ""
}

// privateAddr reports whether v is a LAN-side address (private, link-local
// and the like): the source of a connection a LAN device made.
func privateAddr(v string) bool {
	a, public := enrich.PublicIP(v)
	return a.IsValid() && !public
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

// upsertMatch records a list match: args provider, indicator, kind, verdict,
// now, now, list version, facts (listFacts).
const upsertMatch = `INSERT INTO enrichment (provider, indicator, kind, method, verdict, current,
		first_seen, last_seen, ended_at, version, facts) VALUES (?,?,?,'downloaded',?,1,?,?,'',?,?)
	ON CONFLICT(provider, indicator) DO UPDATE SET verdict = excluded.verdict, facts = excluded.facts,
		current = 1, last_seen = excluded.last_seen, ended_at = '', version = excluded.version`

// markUnlisted records that a list no longer has an indicator: args now,
// list version, provider, indicator.
const markUnlisted = `UPDATE enrichment SET ended_at = CASE WHEN current = 1 THEN ? ELSE ended_at END,
		current = 0, version = ? WHERE provider = ? AND indicator = ?`

// listFacts is what a list says about a match: through which listed IP, CIDR
// or parent domain, and the list's own note for it (e.g. a Spamhaus SBL id).
func listFacts(via, detail string) string {
	m := map[string]string{}
	if via != "" {
		m["matched_via"] = via
	}
	if detail != "" {
		m["detail"] = detail
	}
	b, _ := json.Marshal(m)
	return string(b)
}

type windowInd struct {
	ind, kind string
	hasRow    bool
}

// Reconcile re-checks every indicator seen since `since` against one list's
// current contents: new matches are added, rows still matched are refreshed,
// and rows no longer matched are marked ended (kept, with ended_at).
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
			if _, err := tx.Exec(upsertMatch, prov, w.ind, w.kind, l.Verdict, ts, ts, l.Version, listFacts(via, det)); err != nil {
				return st, err
			}
		case w.hasRow:
			res, err := tx.Exec(markUnlisted+` AND (current = 1 OR version != ?)`, ts, l.Version, prov, w.ind, l.Version)
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
	ips, err := s.column(`SELECT indicator FROM indicators WHERE kind = 'ip' AND last_seen >= ?`, fmtTime(since))
	if err != nil {
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
			if _, err := tx.Exec(upsertMatch, l.Provider(), ind, kind, l.Verdict, ts, ts, l.Version, listFacts(via, det)); err != nil {
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
		WHERE e.method = 'downloaded' AND e.version != v.version AND i.last_seen >= ? GROUP BY e.provider`, fmtTime(since))
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
	// Lookups are queried providers' cached answers (internetdb, abuseipdb,
	// censys): context, not verdicts.
	Lookups map[string]*LookupFacts `json:"queried,omitempty"`
	// Bans30d is how many times fail2ban banned this address in the last 30
	// days, all jails, not counting restores across restarts. That's the
	// window it remembers for doubling repeat bans.
	Bans30d int64 `json:"bans_30d,omitempty"`
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
	for chunk := range slices.Chunk(inds, maxVars) {
		args := make([]any, len(chunk))
		for i, v := range chunk {
			args[i] = v
		}
		in := placeholders(len(chunk))
		current := ` AND current = 1`
		if history {
			current = ``
		}
		// Lists only here: they give verdicts and "on lists". Queried providers'
		// rows are context, read by lookupIntel.
		rows, err := s.query(`SELECT indicator, provider, verdict, coalesce(json_extract(facts, '$.detail'), ''),
			coalesce(json_extract(facts, '$.matched_via'), ''), current, first_seen, last_seen, ended_at
			FROM enrich.enrichment WHERE method = 'downloaded' AND indicator IN (`+in+`)`+current+`
			ORDER BY indicator, current DESC, provider`, args...)
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
		// Queried providers' answers, as context.
		rows, err = s.query(`SELECT indicator, provider, current, last_seen, facts FROM enrich.enrichment
			WHERE method = 'queried' AND indicator IN (`+in+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ind, prov, last, facts string
			var lf LookupFacts
			if err := rows.Scan(&ind, &prov, &lf.Found, &last, &facts); err != nil {
				rows.Close()
				return nil, err
			}
			lf.AsOf = parseTime(last)
			if lf.Found {
				lf.Facts = json.RawMessage(facts)
			}
			in := get(ind)
			if in.Lookups == nil {
				in.Lookups = map[string]*LookupFacts{}
			}
			in.Lookups[prov] = &lf
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
	var ips []string
	for _, ind := range inds {
		if _, err := netip.ParseAddr(ind); err == nil {
			ips = append(ips, ind)
		}
	}
	bans, err := s.BanCounts(ips, time.Now().AddDate(0, 0, -30))
	if err != nil {
		return nil, err
	}
	for ip, n := range bans {
		get(ip).Bans30d = n
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

// indexVersion goes up whenever what gets indexed changes, so the next run
// re-reads every table from the start. Re-reading is safe: indicators only
// widen their first/last seen and gain roles.
//
//	1: first version
//	2: special-use names (ipv4only.arpa) are indexed too
//	3: a connection's destination is RoleConn only when a LAN device was
//	   the source; the old bits are cleared and connections alone re-read
const indexVersion = 3

func (s *Store) resetIndexIfOld() error {
	var v int
	err := s.queryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'index_version'`).Scan(&v)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if v >= indexVersion {
		return nil
	}
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if v < 2 {
		if _, err := tx.Exec(`DELETE FROM cursors`); err != nil {
			return err
		}
	}
	// v3: clear RoleConn (and drop indicators it was the only reason for),
	// then re-read connections under the new rule.
	for _, q := range []string{
		`UPDATE indicators SET roles = roles & ~? WHERE roles & ?`,
		`DELETE FROM enrichment WHERE indicator IN (SELECT indicator FROM indicators WHERE roles = 0)`,
		`DELETE FROM indicators WHERE roles = 0`,
		`DELETE FROM cursors WHERE tbl = 'connections'`,
	} {
		var args []any
		if strings.Count(q, "?") == 2 {
			args = []any{RoleConn, RoleConn}
		}
		if _, err := tx.Exec(q, args...); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO meta (key, value) VALUES ('index_version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, indexVersion); err != nil {
		return err
	}
	return tx.Commit()
}
