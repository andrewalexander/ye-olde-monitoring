package store

import (
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/enrich"
)

// maxIndexedNames caps how many names indexedLookups puts in one IN list;
// past it (a lookup of "com"), the plain scan is no worse.
const maxIndexedNames = 500

// indexedLookups is DNSByDomain for the explorer, with explore.db attached.
// Matching subdomains by suffix can't use the domain index, so it scans every
// query in the window. Instead it takes the matching names from the
// indicator index (one row per name) plus the rows not indexed yet, then
// reads just those names through the index. Names the index doesn't keep
// (internal ones like .lan) still take the scan.
func (s *Store) indexedLookups(domain string, since time.Time) ([]ClientLookups, error) {
	d, public := enrich.PublicDomain(domain)
	if _, special := enrich.SpecialDomain(d); (!public && !special) || d != domain {
		return s.DNSByDomain(domain, since)
	}
	names := map[string]bool{domain: true}
	collect := func(q string, args ...any) error {
		ns, err := s.column(q, args...)
		for _, n := range ns {
			names[n] = true
		}
		return err
	}
	if err := collect(`SELECT indicator FROM enrich.indicators WHERE kind = 'domain'
		AND length(indicator) > length(?1) AND substr(indicator, -length(?1)-1) = '.' || ?1`, domain); err != nil {
		return nil, err
	}
	// Rows the index hasn't read yet: only those past its cursor.
	if err := collect(`SELECT DISTINCT domain FROM dns_queries
		WHERE id > coalesce((SELECT last_id FROM enrich.cursors WHERE tbl = 'dns_queries'), 0) AND `+domainMatch, domain); err != nil {
		return nil, err
	}
	if len(names) > maxIndexedNames {
		return s.DNSByDomain(domain, since)
	}
	args := []any{fmtTime(since)}
	marks := make([]string, 0, len(names))
	for n := range names {
		args = append(args, n)
		marks = append(marks, "?")
	}
	return s.clientLookups(`ts >= ?1 AND domain IN (`+strings.Join(marks, ",")+`)`, args...)
}
