package store

import (
	"cmp"
	"database/sql"
	"slices"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/enrich"
)

// The queries here need the explorer's database attached as "enrich"
// (OpenReadOnly). They join what came in and went out with the feeds.

// ClientCount is a LAN device and how many times it did something.
type ClientCount struct {
	IP    string `json:"ip"`
	Name  string `json:"name,omitempty"` // from DHCP, UniFi or the neighbour table
	Count int64  `json:"count"`
}

func (s *Store) lanClients() (map[string]bool, error) {
	rows, err := s.query(`SELECT ip FROM enrich.lan_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

// IsLAN says whether ip is private or has used the router's DNS.
func (s *Store) IsLAN(ip string) (bool, error) {
	a, public := enrich.PublicIP(ip)
	if !public {
		return a.IsValid(), nil
	}
	var n int
	err := s.queryRow(`SELECT count(*) FROM enrich.lan_clients WHERE ip = ?`, a.String()).Scan(&n)
	return n > 0, err
}

// InboundIP is one public address that reached us, with everything it did.
type InboundIP struct {
	IP            string    `json:"ip"`
	Hits          int64     `json:"hits"`
	Errors4xx     int64     `json:"errors_4xx"`
	First         time.Time `json:"first,omitzero"`
	Last          time.Time `json:"last,omitzero"`
	Sites         []string  `json:"sites,omitempty"`
	Bans          int64     `json:"bans"`
	Leaks         int64     `json:"leaks"`
	AlertsAllowed int64     `json:"alerts_allowed"`
	AlertsBlocked int64     `json:"alerts_blocked"`
	Trips         int64     `json:"trips"`
	AuthFailures  int64     `json:"auth_failures"`
	*Intel
}

// Order for the explorer's lists.
const (
	OrderFlagged = "flagged" // worst verdict first, then busiest
	OrderTop     = "top"
	OrderBottom  = "bottom"
	OrderNew     = "new"    // first seen inside the window, newest first
	OrderRecent  = "recent" // last seen, newest first
)

func checkOrder(o string) (string, error) {
	switch o {
	case "":
		return OrderFlagged, nil
	case OrderFlagged, OrderTop, OrderBottom, OrderNew, OrderRecent:
		return o, nil
	}
	return "", BadQueryError("order must be flagged, top, bottom, new or recent")
}

// ListQuery is shared by the explorer's lists.
type ListQuery struct {
	Since   time.Time
	Flagged bool // only malicious/suspicious
	Order   string
	Limit   int
}

func (q *ListQuery) norm() error {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	var err error
	q.Order, err = checkOrder(q.Order)
	return err
}

// InboundIPs lists the public addresses that hit our sites, got banned,
// raised IDS alerts or tripped a breaker since q.Since.
func (s *Store) InboundIPs(q ListQuery, now time.Time) ([]InboundIP, error) {
	if err := q.norm(); err != nil {
		return nil, err
	}
	lan, err := s.lanClients()
	if err != nil {
		return nil, err
	}
	since := fmtTime(q.Since)
	m := map[string]*InboundIP{}
	get := func(ip string) *InboundIP {
		a, ok := enrich.PublicIP(ip)
		if !ok || lan[a.String()] {
			return nil
		}
		k := a.String()
		if m[k] == nil {
			m[k] = &InboundIP{IP: k}
		}
		return m[k]
	}
	rows, err := s.query(`SELECT client_ip, count(*), sum(status BETWEEN 400 AND 499), min(ts), max(ts),
		group_concat(DISTINCT site) FROM hits WHERE ts >= ? GROUP BY client_ip`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip, first, last string
		var sites sql.NullString
		var n, e4 int64
		if err := rows.Scan(&ip, &n, &e4, &first, &last, &sites); err != nil {
			rows.Close()
			return nil, err
		}
		if r := get(ip); r != nil {
			r.Hits, r.Errors4xx, r.First, r.Last = n, e4, parseTime(first), parseTime(last)
			if sites.String != "" {
				r.Sites = strings.Split(sites.String, ",")
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	counts := []struct {
		q   string
		set func(*InboundIP, int64, int64)
	}{
		{`SELECT src_ip, sum(action = 'allowed'), sum(action = 'blocked') FROM ids_alerts WHERE ts >= ? GROUP BY src_ip`,
			func(r *InboundIP, a, b int64) { r.AlertsAllowed, r.AlertsBlocked = a, b }},
		{`SELECT key, count(*), 0 FROM breaker_trips WHERE tripped_at >= ? GROUP BY key`,
			func(r *InboundIP, a, _ int64) { r.Trips = a }},
		{`SELECT ip, count(*), 0 FROM auth_failures WHERE ts >= ? GROUP BY ip`,
			func(r *InboundIP, a, _ int64) { r.AuthFailures = a }},
	}
	for _, c := range counts {
		rows, err := s.query(c.q, since)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			var a, b int64
			if err := rows.Scan(&ip, &a, &b); err != nil {
				rows.Close()
				return nil, err
			}
			if r := get(ip); r != nil {
				c.set(r, a, b)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	bans, err := s.Bans(BanFilter{Since: q.Since, Limit: 100000}, now)
	if err != nil {
		return nil, err
	}
	for _, b := range bans {
		if r := get(b.IP); r != nil {
			if !b.Restored {
				r.Bans++
			}
			if b.HitsDuring > 0 {
				r.Leaks++
			}
		}
	}
	out := make([]InboundIP, 0, len(m))
	ips := make([]string, 0, len(m))
	for k, r := range m {
		out = append(out, *r)
		ips = append(ips, k)
	}
	intel, err := s.Intel(ips, false)
	if err != nil {
		return nil, err
	}
	var newSince map[string]bool
	if q.Order == OrderNew {
		if newSince, err = s.firstSeenSince("ip", q.Since); err != nil {
			return nil, err
		}
	}
	keep := out[:0]
	for _, r := range out {
		r.Intel = intel[r.IP]
		if q.Flagged && !r.Intel.Flagged() {
			continue
		}
		if q.Order == OrderNew && !newSince[r.IP] {
			continue
		}
		keep = append(keep, r)
	}
	out = keep
	activity := func(r InboundIP) int64 {
		return r.Hits + r.Bans + r.AlertsAllowed + r.AlertsBlocked + r.Trips + r.AuthFailures
	}
	slices.SortFunc(out, func(a, b InboundIP) int {
		switch q.Order {
		case OrderTop:
		case OrderBottom:
			return cmp.Or(cmp.Compare(activity(a), activity(b)), strings.Compare(a.IP, b.IP))
		case OrderNew:
			return cmp.Or(b.First.Compare(a.First), strings.Compare(a.IP, b.IP))
		case OrderRecent:
			return cmp.Or(b.Last.Compare(a.Last), strings.Compare(a.IP, b.IP))
		default:
			if c := cmp.Compare(verdictOf(b.Intel), verdictOf(a.Intel)); c != 0 {
				return c
			}
		}
		return cmp.Or(cmp.Compare(activity(b), activity(a)), strings.Compare(a.IP, b.IP))
	})
	return out[:min(len(out), q.Limit)], nil
}

// flaggedRank is the verdict rank (enrich.VerdictRank) from which a looked-up
// domain counts as flagged: suspicious or worse.
const flaggedRank = 2

// domainRanker rates a looked-up domain by the worst of its own lists and
// those of the addresses it resolved to since since.
func (s *Store) domainRanker(since time.Time) (func(d string) int, error) {
	listed, err := s.listedDomains()
	if err != nil {
		return nil, err
	}
	answers, err := s.flaggedAnswers(since)
	if err != nil {
		return nil, err
	}
	return func(d string) int {
		norm, _ := enrich.PublicDomain(d)
		r := verdictOf(listed[norm])
		if a := answers[d]; a != nil {
			r = max(r, enrich.VerdictRank(a.Verdict))
		}
		return r
	}, nil
}

func verdictOf(i *Intel) int {
	if i == nil {
		return 0
	}
	return enrich.VerdictRank(i.Verdict)
}

// firstSeenSince is the indicators of kind first seen at or after since.
func (s *Store) firstSeenSince(kind string, since time.Time) (map[string]bool, error) {
	rows, err := s.query(`SELECT indicator FROM enrich.indicators WHERE kind = ? AND first_seen >= ?`, kind, fmtTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// listedDomains is every domain on a list now: domain -> worst verdict and feeds.
func (s *Store) listedDomains() (map[string]*Intel, error) {
	rows, err := s.query(`SELECT indicator, provider, verdict FROM enrich.enrichment WHERE current = 1 AND method = 'downloaded' AND kind = 'domain'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*Intel{}
	for rows.Next() {
		var d, p, v string
		if err := rows.Scan(&d, &p, &v); err != nil {
			return nil, err
		}
		in := out[d]
		if in == nil {
			in = &Intel{}
			out[d] = in
		}
		in.Feeds = append(in.Feeds, p)
		if enrich.VerdictRank(v) > enrich.VerdictRank(in.Verdict) {
			in.Verdict = v
		}
	}
	return out, rows.Err()
}

// AnswerIntel is what's known about the addresses a domain resolved to.
type AnswerIntel struct {
	Verdict string   `json:"verdict,omitempty"`
	Feeds   []string `json:"feeds,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

// flaggedAnswers maps each domain that resolved (since `since`) to a listed
// address, to those addresses' feeds. It starts from the listed addresses,
// which are few, so it uses dns_replies' answer index.
func (s *Store) flaggedAnswers(since time.Time) (map[string]*AnswerIntel, error) {
	rows, err := s.query(`SELECT r.domain, e.indicator, e.provider, e.verdict
		FROM enrich.enrichment e CROSS JOIN dns_replies r ON r.answer = e.indicator
		WHERE e.current = 1 AND e.method = 'downloaded' AND e.kind = 'ip' AND r.ts >= ?
		GROUP BY r.domain, e.indicator, e.provider`, fmtTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*AnswerIntel{}
	for rows.Next() {
		var d, ip, p, v string
		if err := rows.Scan(&d, &ip, &p, &v); err != nil {
			return nil, err
		}
		if enrich.Reserved(ip) {
			continue // e.g. ipv4only.arpa -> 192.0.0.170: not a host
		}
		a := out[d]
		if a == nil {
			a = &AnswerIntel{}
			out[d] = a
		}
		if !slices.Contains(a.Feeds, p) {
			a.Feeds = append(a.Feeds, p)
		}
		if !slices.Contains(a.IPs, ip) {
			a.IPs = append(a.IPs, ip)
		}
		if enrich.VerdictRank(v) > enrich.VerdictRank(a.Verdict) {
			a.Verdict = v
		}
	}
	return out, rows.Err()
}

// DomainRow is one domain the LAN looked up.
type DomainRow struct {
	Domain  string       `json:"domain"`
	Lookups int64        `json:"lookups"`
	Clients int64        `json:"clients"`
	First   time.Time    `json:"first"`
	Last    time.Time    `json:"last"`
	Blocked int64        `json:"blocked"`
	New     bool         `json:"new"` // first ever looked up inside the window
	Answers *AnswerIntel `json:"answers,omitempty"`
	*Intel
}

func (d *DomainRow) rank() int {
	r := verdictOf(d.Intel)
	if d.Answers != nil {
		r = max(r, enrich.VerdictRank(d.Answers.Verdict))
	}
	return r
}

// Domains lists the domains looked up since q.Since, with their feeds and
// the feeds of the addresses they resolved to.
func (s *Store) Domains(q ListQuery) ([]DomainRow, error) {
	if err := q.norm(); err != nil {
		return nil, err
	}
	rows, err := s.query(`SELECT domain, count(*), count(DISTINCT client_ip), min(ts), max(ts)
		FROM dns_queries WHERE ts >= ? GROUP BY domain`, fmtTime(q.Since))
	if err != nil {
		return nil, err
	}
	var out []DomainRow
	for rows.Next() {
		var d DomainRow
		var first, last string
		if err := rows.Scan(&d.Domain, &d.Lookups, &d.Clients, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		d.First, d.Last = parseTime(first), parseTime(last)
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	listed, err := s.listedDomains()
	if err != nil {
		return nil, err
	}
	answers, err := s.flaggedAnswers(q.Since)
	if err != nil {
		return nil, err
	}
	fresh, err := s.firstSeenSince("domain", q.Since)
	if err != nil {
		return nil, err
	}
	keep := out[:0]
	for _, d := range out {
		norm, _ := enrich.PublicDomain(d.Domain)
		d.Intel, d.Answers, d.New = listed[norm], answers[d.Domain], fresh[norm]
		if sp, ok := enrich.SpecialDomain(norm); ok {
			in := &Intel{Special: &sp}
			if d.Intel != nil {
				in.Feeds = d.Intel.Feeds
			}
			if sp.Reserved {
				in.Verdict = enrich.VerdictReserved
			}
			d.Intel = in
		}
		if q.Flagged && d.rank() < 2 {
			continue
		}
		if q.Order == OrderNew && !d.New {
			continue
		}
		keep = append(keep, d)
	}
	out = keep
	slices.SortFunc(out, func(a, b DomainRow) int {
		switch q.Order {
		case OrderTop:
		case OrderBottom:
			return cmp.Or(cmp.Compare(a.Lookups, b.Lookups), strings.Compare(a.Domain, b.Domain))
		case OrderNew:
			return cmp.Or(b.First.Compare(a.First), strings.Compare(a.Domain, b.Domain))
		case OrderRecent:
			return cmp.Or(b.Last.Compare(a.Last), strings.Compare(a.Domain, b.Domain))
		default:
			if c := cmp.Compare(b.rank(), a.rank()); c != 0 {
				return c
			}
		}
		return cmp.Or(cmp.Compare(b.Lookups, a.Lookups), strings.Compare(a.Domain, b.Domain))
	})
	out = out[:min(len(out), q.Limit)]
	for i := range out {
		if err := s.queryRow(`SELECT count(*) FROM dns_replies WHERE domain = ? AND status = 'blocked' AND ts >= ?`,
			out[i].Domain, fmtTime(q.Since)).Scan(&out[i].Blocked); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ClientRow is one LAN device's lookups.
type ClientRow struct {
	IP             string    `json:"ip"`
	Name           string    `json:"name,omitempty"`
	MAC            string    `json:"mac,omitempty"`
	Network        string    `json:"network,omitempty"`
	Lookups        int64     `json:"lookups"`
	Domains        int64     `json:"domains"`
	NewDomains     int64     `json:"new_domains"`
	Flagged        int64     `json:"flagged_domains"`
	FlaggedSamples []string  `json:"flagged_samples,omitempty"` // up to 5, worst first
	First          time.Time `json:"first"`
	Last           time.Time `json:"last"`
}

// Clients lists the LAN devices that looked things up since `since`, and how
// many of those lookups were flagged (directly, or by what they resolved to).
func (s *Store) Clients(since time.Time) ([]ClientRow, error) {
	rank, err := s.domainRanker(since)
	if err != nil {
		return nil, err
	}
	fresh, err := s.firstSeenSince("domain", since)
	if err != nil {
		return nil, err
	}
	rows, err := s.query(`SELECT client_ip, domain, count(*), max(client_name), min(ts), max(ts)
		FROM dns_queries WHERE ts >= ? GROUP BY client_ip, domain`, fmtTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type flaggedDomain struct {
		d    string
		rank int
		n    int64
	}
	m := map[string]*ClientRow{}
	flagged := map[string][]flaggedDomain{}
	for rows.Next() {
		var ip, d, first, last string
		var name sql.NullString
		var n int64
		if err := rows.Scan(&ip, &d, &n, &name, &first, &last); err != nil {
			return nil, err
		}
		c := m[ip]
		if c == nil {
			c = &ClientRow{IP: ip, First: parseTime(first), Last: parseTime(last)}
			m[ip] = c
		}
		if name.String != "" {
			c.Name = name.String
		}
		c.Lookups += n
		c.Domains++
		if f := parseTime(first); f.Before(c.First) {
			c.First = f
		}
		if l := parseTime(last); l.After(c.Last) {
			c.Last = l
		}
		norm, _ := enrich.PublicDomain(d)
		if fresh[norm] {
			c.NewDomains++
		}
		if r := rank(d); r >= flaggedRank {
			c.Flagged++
			flagged[ip] = append(flagged[ip], flaggedDomain{d, rank(d), n})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]ClientRow, 0, len(m))
	for ip, c := range m {
		fs := flagged[ip]
		slices.SortFunc(fs, func(a, b flaggedDomain) int { return cmp.Or(b.rank-a.rank, cmp.Compare(b.n, a.n)) })
		for _, f := range fs[:min(5, len(fs))] {
			c.FlaggedSamples = append(c.FlaggedSamples, f.d)
		}
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b ClientRow) int {
		return cmp.Or(cmp.Compare(b.Flagged, a.Flagged), cmp.Compare(b.Lookups, a.Lookups), strings.Compare(a.IP, b.IP))
	})
	ips := make([]string, len(out))
	for i, c := range out {
		ips[i] = c.IP
	}
	dev, err := s.Devices(ips, time.Time{})
	if err != nil {
		return nil, err
	}
	for i := range out {
		if d, ok := dev[out[i].IP]; ok {
			out[i].MAC, out[i].Network = d.MAC, d.Network
			if out[i].Name == "" {
				out[i].Name = d.Name
			}
		}
	}
	return out, nil
}

// FlaggedRow is one listed indicator seen in the window, and who it involved.
type FlaggedRow struct {
	Indicator string    `json:"indicator"`
	Kind      string    `json:"kind"`
	Direction string    `json:"direction"` // in | out | both
	First     time.Time `json:"first_seen"`
	Last      time.Time `json:"last_seen"`
	// Incoming: requests to our sites, bans and IDS alerts in the window.
	Hits   int64    `json:"hits,omitempty"`
	Sites  []string `json:"sites,omitempty"`
	Bans   int64    `json:"bans,omitempty"`
	Alerts int64    `json:"alerts,omitempty"`
	// Outgoing: the LAN devices that looked it up (or, for an address, looked
	// up a name that resolved to it), and those names.
	Clients []ClientCount `json:"clients,omitempty"`
	Via     []string      `json:"via_domains,omitempty"`
	*Intel
}

// FlaggedQuery selects flagged indicators.
type FlaggedQuery struct {
	Since time.Time
	// Verdicts to include; empty means malicious and suspicious. "reserved"
	// adds special-purpose addresses and names (RFC 6890, ipv4only.arpa),
	// which are never flagged otherwise.
	Verdicts []string
	Limit    int
}

// Flagged lists every indicator on a list now that was seen since q.Since,
// worst and most recent first.
func (s *Store) Flagged(q FlaggedQuery) ([]FlaggedRow, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if len(q.Verdicts) == 0 {
		q.Verdicts = []string{enrich.Malicious, enrich.Suspicious}
	}
	type candidate struct {
		ind, kind, first, last string
		role, rank             int
	}
	var cands []candidate
	var listedArgs []any
	wantReserved := false
	for _, v := range q.Verdicts {
		switch {
		case v == enrich.VerdictReserved:
			wantReserved = true
		case enrich.VerdictRank(v) > 0:
			listedArgs = append(listedArgs, v)
		default:
			return nil, BadQueryError("verdict must be malicious, suspicious, info or reserved")
		}
	}
	since := fmtTime(q.Since)
	scan := func(rows *sql.Rows, keep func(*candidate) bool) error {
		defer rows.Close()
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.ind, &c.kind, &c.role, &c.first, &c.last, &c.rank); err != nil {
				return err
			}
			if keep(&c) {
				cands = append(cands, c)
			}
		}
		return rows.Err()
	}
	if len(listedArgs) > 0 {
		in := strings.TrimSuffix(strings.Repeat("?,", len(listedArgs)), ",")
		rows, err := s.query(`SELECT i.indicator, i.kind, i.roles, i.first_seen, i.last_seen,
				max(CASE e.verdict WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 ELSE 1 END) AS rank
			FROM enrich.enrichment e JOIN enrich.indicators i ON i.indicator = e.indicator
			WHERE `+listedNotLAN+` AND i.last_seen >= ? AND e.verdict IN (`+in+`)
			GROUP BY i.indicator`, append([]any{since}, listedArgs...)...)
		if err != nil {
			return nil, err
		}
		// Reserved addresses (and names) aren't hosts: a list matching them
		// says nothing, so they only come back when asked for as "reserved".
		if err := scan(rows, func(c *candidate) bool { return !enrich.Reserved(c.ind) }); err != nil {
			return nil, err
		}
	}
	if wantReserved {
		// Few indicators are special-purpose, and which are is decided in Go,
		// so scan the window's indicators for them.
		rows, err := s.query(`SELECT indicator, kind, roles, first_seen, last_seen, 0 FROM enrich.indicators
			WHERE last_seen >= ? AND indicator NOT IN (SELECT ip FROM enrich.lan_clients)`, since)
		if err != nil {
			return nil, err
		}
		if err := scan(rows, func(c *candidate) bool { return enrich.Reserved(c.ind) }); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(cands, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(b.rank, a.rank), strings.Compare(b.last, a.last), strings.Compare(a.ind, b.ind))
	})
	cands = cands[:min(len(cands), q.Limit)]
	out := make([]FlaggedRow, 0, len(cands))
	roles := make([]int, 0, len(cands))
	for _, c := range cands {
		r := FlaggedRow{Indicator: c.ind, Kind: c.kind, First: parseTime(c.first), Last: parseTime(c.last)}
		switch {
		case c.role&RolesIn != 0 && c.role&RolesOut != 0:
			r.Direction = "both"
		case c.role&RolesIn != 0:
			r.Direction = "in"
		default:
			r.Direction = "out"
		}
		out = append(out, r)
		roles = append(roles, c.role)
	}
	inds := make([]string, len(out))
	for i, r := range out {
		inds[i] = r.Indicator
	}
	intel, err := s.Intel(inds, false)
	if err != nil {
		return nil, err
	}
	for i := range out {
		r := &out[i]
		r.Intel = intel[r.Indicator]
		if r.Kind == "domain" {
			if r.Clients, err = s.clientCounts([]string{r.Indicator}, since); err != nil {
				return nil, err
			}
			continue
		}
		if roles[i]&RolesIn != 0 {
			var sites sql.NullString
			if err := s.queryRow(`SELECT count(*), group_concat(DISTINCT site) FROM hits WHERE client_ip = ? AND ts >= ?`,
				r.Indicator, since).Scan(&r.Hits, &sites); err != nil {
				return nil, err
			}
			if sites.String != "" {
				r.Sites = strings.Split(sites.String, ",")
			}
			if err := s.queryRow(`SELECT count(*) FROM ids_alerts WHERE src_ip = ? AND ts >= ?`, r.Indicator, since).Scan(&r.Alerts); err != nil {
				return nil, err
			}
			bc, err := s.BanCounts([]string{r.Indicator}, q.Since)
			if err != nil {
				return nil, err
			}
			r.Bans = bc[r.Indicator]
		}
		if roles[i]&RolesOut != 0 {
			if r.Via, err = s.domainsResolvingTo(r.Indicator, since, 20); err != nil {
				return nil, err
			}
			if r.Clients, err = s.clientCounts(r.Via, since); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func (s *Store) domainsResolvingTo(ip, since string, limit int) ([]string, error) {
	rows, err := s.query(`SELECT domain FROM dns_replies WHERE answer = ? AND ts >= ?
		GROUP BY domain ORDER BY count(*) DESC LIMIT ?`, ip, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) clientCounts(domains []string, since string) ([]ClientCount, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	args := []any{since}
	for _, d := range domains {
		args = append(args, d)
	}
	rows, err := s.query(`SELECT client_ip, count(*) FROM dns_queries WHERE ts >= ? AND domain IN (`+
		strings.TrimSuffix(strings.Repeat("?,", len(domains)), ",")+`) GROUP BY client_ip ORDER BY 2 DESC`, args...)
	if err != nil {
		return nil, err
	}
	var out []ClientCount
	for rows.Next() {
		var c ClientCount
		if err := rows.Scan(&c.IP, &c.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, s.nameCounts(out)
}

// ResolvedFrom is a name that resolved to an address, and who looked it up.
type ResolvedFrom struct {
	Domain  string        `json:"domain"`
	Count   int64         `json:"count"`
	Last    time.Time     `json:"last"`
	Clients []ClientCount `json:"clients,omitempty"`
}

// ASNChange is an address whose AS changed between iptoasn versions.
type ASNChange struct {
	TS       time.Time `json:"ts"`
	OldASN   uint32    `json:"old_asn"`
	NewASN   uint32    `json:"new_asn"`
	OldOwner string    `json:"old_owner"`
	NewOwner string    `json:"new_owner"`
}

// IPProfile is everything about one address.
type IPProfile struct {
	IP      string    `json:"ip"`
	LAN     bool      `json:"lan"`
	Intel   *Intel    `json:"intel,omitempty"`
	History IPHistory `json:"history"`
	Hits    []hit.Hit `json:"hits"`
	Bans    []Ban     `json:"bans"`
	Alerts  []Alert   `json:"alerts"`
	Trips   []Trip    `json:"trips"`
	// Logins an app refused from this address, with the name tried.
	AuthFailures []AuthFailure `json:"auth_failures"`
	// Router firewall lines with this address at either end.
	Connections []ConnStat     `json:"connections"`
	ResolvedBy  []ResolvedFrom `json:"resolved_from"`
	ASNChanges  []ASNChange    `json:"asn_changes,omitempty"`
	// For LAN addresses: the device there now, and its sightings (DHCP,
	// UniFi, neighbour table), across every address it has used.
	Device    *Device    `json:"device,omitempty"`
	Sightings []Sighting `json:"sightings,omitempty"`
	// For LAN addresses: what it looked up, flagged first.
	Lookups []FlaggedLookup `json:"lookups,omitempty"`
}

// FlaggedLookup is one domain a LAN client looked up, and whether it (or
// an address it resolved to) is listed suspicious or worse.
type FlaggedLookup struct {
	DomainLookups
	Flagged bool `json:"flagged"`
}

// profileLookups is how many domains a LAN address's profile lists.
const profileLookups = 500

// IPProfile gathers one address's activity since `since` (its history
// counts are all-time).
func (s *Store) IPProfile(ip string, since, now time.Time) (IPProfile, error) {
	p := IPProfile{IP: ip}
	var err error
	if p.LAN, err = s.IsLAN(ip); err != nil {
		return p, err
	}
	intel, err := s.Intel([]string{ip}, true)
	if err != nil {
		return p, err
	}
	p.Intel = intel[ip]
	if p.History, err = s.IPHistory(ip); err != nil {
		return p, err
	}
	if p.LAN {
		dev, err := s.Devices([]string{ip}, time.Time{})
		if err != nil {
			return p, err
		}
		if d, ok := dev[ip]; ok {
			p.Device = &d
		}
		if p.Sightings, err = s.DeviceSightings(ip, 50); err != nil {
			return p, err
		}
		if p.Lookups, err = s.flaggedLookups(ip, since); err != nil {
			return p, err
		}
	}
	if p.Hits, err = s.Hits(HitFilter{IP: ip, Since: since, Limit: 50}); err != nil {
		return p, err
	}
	if p.Bans, err = s.Bans(BanFilter{IP: ip, Since: since, Limit: 50}, now); err != nil {
		return p, err
	}
	if p.Alerts, err = s.Alerts(AlertFilter{IP: ip, Since: since, Limit: 50}); err != nil {
		return p, err
	}
	if p.Trips, err = s.Trips(TripFilter{Key: ip, Since: since, Limit: 50}); err != nil {
		return p, err
	}
	if p.AuthFailures, err = s.AuthFailures(ip, since, 50); err != nil {
		return p, err
	}
	if p.Connections, err = s.ConnsForIP(ip, since, 200); err != nil {
		return p, err
	}
	sinceS := fmtTime(since)
	rows, err := s.query(`SELECT domain, count(*), max(ts) FROM dns_replies WHERE answer = ? AND ts >= ?
		GROUP BY domain ORDER BY 2 DESC LIMIT 50`, ip, sinceS)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var r ResolvedFrom
		var last string
		if err := rows.Scan(&r.Domain, &r.Count, &last); err != nil {
			rows.Close()
			return p, err
		}
		r.Last = parseTime(last)
		p.ResolvedBy = append(p.ResolvedBy, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, err
	}
	for i := range p.ResolvedBy {
		if p.ResolvedBy[i].Clients, err = s.clientCounts([]string{p.ResolvedBy[i].Domain}, sinceS); err != nil {
			return p, err
		}
	}
	rows, err = s.query(`SELECT ts, old_asn, new_asn, old_owner, new_owner FROM enrich.ip_asn_changes
		WHERE ip = ? ORDER BY ts DESC LIMIT 20`, ip)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var c ASNChange
		var ts string
		if err := rows.Scan(&ts, &c.OldASN, &c.NewASN, &c.OldOwner, &c.NewOwner); err != nil {
			return p, err
		}
		c.TS = parseTime(ts)
		p.ASNChanges = append(p.ASNChanges, c)
	}
	return p, rows.Err()
}

// Answer is one address a domain resolved to.
type Answer struct {
	Answer string    `json:"answer"`
	Status string    `json:"status"`
	Count  int64     `json:"count"`
	Last   time.Time `json:"last"`
	*Intel
}

// DomainProfile is everything about one domain (and its subdomains, for lookups).
type DomainProfile struct {
	Domain      string          `json:"domain"`
	Intel       *Intel          `json:"intel,omitempty"`
	Lookups     []ClientLookups `json:"lookups"`
	Answers     []Answer        `json:"answers"`
	Connections []ConnStat      `json:"connections"`
}

// DomainProfile gathers one domain's lookups, answers and connections.
func (s *Store) DomainProfile(d string, since time.Time) (DomainProfile, error) {
	p := DomainProfile{Domain: d}
	norm, _ := enrich.PublicDomain(d)
	intel, err := s.Intel([]string{norm}, true)
	if err != nil {
		return p, err
	}
	p.Intel = intel[norm]
	if p.Lookups, err = s.indexedLookups(d, since); err != nil {
		return p, err
	}
	if p.Connections, err = s.ConnsForDomain(d, since); err != nil {
		return p, err
	}
	rows, err := s.query(`SELECT answer, status, count(*), max(ts) FROM dns_replies WHERE domain = ? AND ts >= ?
		GROUP BY answer, status ORDER BY 3 DESC LIMIT 100`, d, fmtTime(since))
	if err != nil {
		return p, err
	}
	var ips []string
	for rows.Next() {
		var a Answer
		var last string
		if err := rows.Scan(&a.Answer, &a.Status, &a.Count, &last); err != nil {
			rows.Close()
			return p, err
		}
		a.Last = parseTime(last)
		p.Answers = append(p.Answers, a)
		ips = append(ips, a.Answer)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, err
	}
	ai, err := s.Intel(ips, false)
	if err != nil {
		return p, err
	}
	for i := range p.Answers {
		p.Answers[i].Intel = ai[p.Answers[i].Answer]
	}
	return p, nil
}

// nameCounts names the LAN devices in counts.
func (s *Store) nameCounts(cs []ClientCount) error {
	ips := make([]string, len(cs))
	for i, c := range cs {
		ips[i] = c.IP
	}
	dev, err := s.Devices(ips, time.Time{})
	for i := range cs {
		cs[i].Name = dev[cs[i].IP].Name
	}
	return err
}

// listedNotLAN is what makes an enrichment row count as flagged, alongside
// its verdict: a current downloaded-list match on something that isn't a
// LAN device. Reserved addresses are filtered in Go (enrich.Reserved).
const listedNotLAN = `e.current = 1 AND e.method = 'downloaded'
	AND e.indicator NOT IN (SELECT ip FROM enrich.lan_clients)`

// Overview is the explorer's landing page numbers.
type Overview struct {
	// Tables is rows (all time) and last_24h, by table.
	Tables     map[string]map[string]int64
	Indicators int64
	// Flagged counts indicators as the Flagged view does: listed malicious
	// or suspicious, not a LAN device, not reserved.
	Flagged int64
}

func (s *Store) Overview(now time.Time) (Overview, error) {
	o := Overview{Tables: map[string]map[string]int64{}}
	day := fmtTime(now.Add(-24 * time.Hour))
	for _, t := range []struct{ table, ts string }{
		{"hits", "ts"}, {"dns_queries", "ts"}, {"dns_replies", ""}, {"connections", ""},
		{"ids_alerts", "ts"}, {"bans", "ts"}, {"breaker_trips", "tripped_at"}, {"auth_failures", "ts"},
	} {
		c := map[string]int64{}
		var rows int64
		// Rows are never deleted, so the largest id is the row count without a scan.
		if err := s.queryRow(`SELECT coalesce(max(id), 0) FROM ` + t.table).Scan(&rows); err != nil {
			return o, err
		}
		c["rows"] = rows
		if t.ts != "" {
			var n int64
			if err := s.queryRow(`SELECT count(*) FROM `+t.table+` WHERE `+t.ts+` >= ?`, day).Scan(&n); err != nil {
				return o, err
			}
			c["last_24h"] = n
		}
		o.Tables[t.table] = c
	}
	if err := s.queryRow(`SELECT count(*) FROM enrich.indicators`).Scan(&o.Indicators); err != nil {
		return o, err
	}
	rows, err := s.query(`SELECT DISTINCT e.indicator FROM enrich.enrichment e
		WHERE ` + listedNotLAN + ` AND e.verdict IN ('malicious','suspicious')`)
	if err != nil {
		return o, err
	}
	defer rows.Close()
	for rows.Next() {
		var ind string
		if err := rows.Scan(&ind); err != nil {
			return o, err
		}
		if !enrich.Reserved(ind) {
			o.Flagged++
		}
	}
	return o, rows.Err()
}

func (s *Store) flaggedLookups(ip string, since time.Time) ([]FlaggedLookup, error) {
	lookups, err := s.DNSByClient(ip, since, profileLookups)
	if err != nil || len(lookups) == 0 {
		return nil, err
	}
	rank, err := s.domainRanker(since)
	if err != nil {
		return nil, err
	}
	out := make([]FlaggedLookup, len(lookups))
	for i, l := range lookups {
		out[i] = FlaggedLookup{l, rank(l.Domain) >= flaggedRank}
	}
	// Flagged first; DNSByClient already ordered each group by count.
	slices.SortStableFunc(out, func(a, b FlaggedLookup) int {
		if a.Flagged == b.Flagged {
			return 0
		}
		if a.Flagged {
			return -1
		}
		return 1
	})
	return out, nil
}
