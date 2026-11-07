package store

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/enrich"
)

// LANAddresses is every address seen as a LAN device: used the router's DNS
// (the explorer's lan_clients) or appeared in DHCP, UniFi client events or
// the neighbour table (lan_sightings). The privacy gate refuses all of them.
// It needs the explorer's database attached (OpenReadOnly).
func (s *Store) LANAddresses() (map[string]bool, error) {
	ips, err := s.column(`SELECT ip FROM enrich.lan_clients UNION SELECT ip FROM lan_sightings WHERE ip != ''`)
	out := map[string]bool{}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil {
			out[a.Unmap().String()] = true
		}
	}
	return out, err
}

// Candidate is an indicator worth asking a queried provider about.
type Candidate struct {
	Indicator string
	Kind      string // ip | domain
	Reason    string // why it was picked, for dry runs
	verdict   int
	outgoing  bool
	bans      int64
	alerts    int64
	hits      int64
}

// LookupCandidates lists what's worth asking about since `since`, worst
// first: inbound addresses that are on a list, banned, raised IDS alerts or
// tripped a breaker; then flagged domains the LAN looked up and the
// addresses they resolved to. At the same verdict, inbound comes first.
// The privacy gate is applied by the caller, not here.
func (s *Store) LookupCandidates(since, now time.Time) ([]Candidate, error) {
	var out []Candidate
	seen := map[string]bool{}
	add := func(c Candidate) {
		if !seen[c.Indicator] {
			seen[c.Indicator] = true
			out = append(out, c)
		}
	}
	in, err := s.InboundIPs(ListQuery{Since: since, Limit: 1 << 20}, now)
	if err != nil {
		return nil, err
	}
	for _, r := range in {
		alerts := r.AlertsAllowed + r.AlertsBlocked
		if !r.Intel.Flagged() && r.Bans == 0 && alerts == 0 && r.Trips == 0 && r.AuthFailures == 0 {
			continue
		}
		c := Candidate{Indicator: r.IP, Kind: "ip", verdict: verdictOf(r.Intel), alerts: alerts, hits: r.Hits}
		var why []string
		if r.Intel != nil {
			c.bans = r.Bans30d
			if r.Intel.Flagged() {
				why = append(why, r.Verdict+" ("+strings.Join(shortFeeds(r.Feeds), ", ")+")")
			}
		}
		if c.bans > 0 {
			why = append(why, fmt.Sprintf("banned %d× in 30d", c.bans))
		}
		if alerts > 0 {
			why = append(why, fmt.Sprintf("%d IDS alert(s)", alerts))
		}
		if r.Trips > 0 {
			why = append(why, fmt.Sprintf("%d breaker trip(s)", r.Trips))
		}
		if r.AuthFailures > 0 {
			why = append(why, fmt.Sprintf("%d refused login(s)", r.AuthFailures))
		}
		if r.Hits > 0 {
			why = append(why, fmt.Sprintf("%d hits", r.Hits))
		}
		c.Reason = "inbound: " + strings.Join(why, "; ")
		add(c)
	}

	doms, err := s.Domains(ListQuery{Since: since, Flagged: true, Limit: 1 << 20})
	if err != nil {
		return nil, err
	}
	for _, d := range doms {
		rank := d.rank()
		if d.Intel.Flagged() {
			add(Candidate{Indicator: d.Domain, Kind: "domain", verdict: rank, outgoing: true, hits: d.Lookups,
				Reason: fmt.Sprintf("outgoing: %s domain (%s); %d lookups", d.Verdict, strings.Join(shortFeeds(d.Feeds), ", "), d.Lookups)})
		}
		answers, err := s.column(`SELECT DISTINCT answer FROM dns_replies WHERE domain = ? AND ts >= ?`, d.Domain, fmtTime(since))
		if err != nil {
			return nil, err
		}
		var ips []string
		for _, a := range answers {
			if ip, err := netip.ParseAddr(a); err == nil {
				ips = append(ips, ip.Unmap().String())
			}
		}
		for _, ip := range ips {
			add(Candidate{Indicator: ip, Kind: "ip", verdict: rank, outgoing: true, hits: d.Lookups,
				Reason: "outgoing: " + d.Domain + " (flagged) resolved to it"})
		}
	}
	slices.SortStableFunc(out, func(a, b Candidate) int {
		return cmp.Or(
			cmp.Compare(b.verdict, a.verdict),
			cmpBool(a.outgoing, b.outgoing),
			cmp.Compare(b.bans, a.bans),
			cmp.Compare(b.alerts, a.alerts),
			cmp.Compare(b.hits, a.hits),
		)
	})
	return out, nil
}

// cmpBool sorts false before true.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

func shortFeeds(fs []string) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = strings.TrimPrefix(f, "feed:")
	}
	return out
}

// FreshLookups is which of inds have an answer from provider newer than ttl
// (found or not): they aren't asked about again yet.
func (s *Store) FreshLookups(provider string, inds []string, ttl time.Duration, now time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	for chunk := range slices.Chunk(inds, maxVars) {
		args := []any{provider, fmtTime(now.Add(-ttl))}
		for _, i := range chunk {
			args = append(args, i)
		}
		fresh, err := s.column(`SELECT indicator FROM enrichment WHERE provider = ? AND method = 'queried'
			AND last_seen >= ? AND indicator IN (`+placeholders(len(chunk))+`)`, args...)
		if err != nil {
			return nil, err
		}
		for _, i := range fresh {
			out[i] = true
		}
	}
	return out, nil
}

// LookupUnits is how much of provider's quota requests used since `since`.
func (s *Store) LookupUnits(provider string, since time.Time) (int, error) {
	var n int
	err := s.queryRow(`SELECT coalesce(sum(units), 0) FROM lookup_requests WHERE provider = ? AND ts >= ?`,
		provider, fmtTime(since)).Scan(&n)
	return n, err
}

// LogLookup records one request sent to a queried provider.
func (s *Store) LogLookup(provider string, inds []string, status string, units int, errMsg string, now time.Time) error {
	_, err := s.exec(`INSERT INTO lookup_requests (provider, indicator, ts, status, units, error) VALUES (?,?,?,?,?,?)`,
		provider, strings.Join(inds, ","), fmtTime(now), status, units, errMsg)
	return err
}

// SaveLookups stores a provider's answers in the enrichment store, one row
// per indicator: current says whether the provider found anything; a row
// that was found and now isn't gets ended_at.
func (s *Store) SaveLookups(provider string, kinds map[string]string, answers []enrich.Answer, now time.Time) error {
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ts := fmtTime(now)
	for _, a := range answers {
		facts := []byte("{}")
		if a.Found && a.Facts != nil {
			if facts, err = json.Marshal(a.Facts); err != nil {
				return err
			}
		}
		kind := kinds[a.Indicator]
		if kind == "" {
			kind = "ip"
		}
		if _, err := tx.Exec(`INSERT INTO enrichment (provider, indicator, kind, method, verdict, current,
				first_seen, last_seen, ended_at, version, facts, raw) VALUES (?,?,?,'queried','',?,?,?,'',?,?,?)
			ON CONFLICT(provider, indicator) DO UPDATE SET current = excluded.current, last_seen = excluded.last_seen,
				ended_at = CASE WHEN excluded.current = 1 THEN ''
					WHEN enrichment.current = 1 THEN excluded.last_seen ELSE enrichment.ended_at END,
				version = excluded.version, facts = excluded.facts, raw = excluded.raw`,
			provider, a.Indicator, kind, a.Found, ts, ts, ts, string(facts), string(a.Raw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RebuildLists drops every downloaded row and list version, so the explorer
// reconciles every list and re-matches every indicator from scratch. Queried
// answers (which cost quota to get again) are kept.
func (s *Store) RebuildLists() error {
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM enrichment WHERE method = 'downloaded'`,
		`DELETE FROM feed_versions WHERE provider LIKE 'feed:%'`,
		`UPDATE indicators SET checked_at = ''`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LookupFacts is one queried provider's cached answer about an indicator.
type LookupFacts struct {
	Found bool            `json:"found"`
	AsOf  time.Time       `json:"as_of"`
	Facts json.RawMessage `json:"facts,omitempty"`
}

// ProviderUsage is how much of a queried provider's quota has been used.
type ProviderUsage struct {
	Provider  string    `json:"provider"`
	Day       int       `json:"units_24h"`
	Month     int       `json:"units_month"`
	Cached    int       `json:"cached"`
	LastAt    time.Time `json:"last_request,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	ErrorAt   time.Time `json:"last_error_at,omitzero"`
}

// LookupUsage reports each queried provider's usage, for the Health page.
// It reads the explorer's own database (s is OpenEnrich's store, or the
// read-only one with it attached as "enrich": pass the table prefix).
func (s *Store) LookupUsage(prefix string, now time.Time) ([]ProviderUsage, error) {
	month := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	rows, err := s.query(`SELECT provider,
			coalesce(sum(CASE WHEN ts >= ? THEN units END), 0),
			coalesce(sum(CASE WHEN ts >= ? THEN units END), 0),
			max(ts)
		FROM `+prefix+`lookup_requests GROUP BY provider ORDER BY provider`,
		fmtTime(now.Add(-24*time.Hour)), fmtTime(month))
	if err != nil {
		return nil, err
	}
	var out []ProviderUsage
	for rows.Next() {
		var u ProviderUsage
		var last string
		if err := rows.Scan(&u.Provider, &u.Day, &u.Month, &last); err != nil {
			rows.Close()
			return nil, err
		}
		u.LastAt = parseTime(last)
		out = append(out, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		u := &out[i]
		if err := s.queryRow(`SELECT count(*) FROM `+prefix+`enrichment WHERE provider = ? AND method = 'queried'`,
			u.Provider).Scan(&u.Cached); err != nil {
			return nil, err
		}
		var msg, ts string
		err := s.queryRow(`SELECT error, ts FROM `+prefix+`lookup_requests WHERE provider = ? AND error != ''
			ORDER BY ts DESC LIMIT 1`, u.Provider).Scan(&msg, &ts)
		switch {
		case err == sql.ErrNoRows:
		case err != nil:
			return nil, err
		default:
			u.LastError, u.ErrorAt = msg, parseTime(ts)
		}
	}
	return out, nil
}
