// Package enrich matches dnscount's indicators (IPs and domains) against
// free threat feeds and an IP→ASN table, all downloaded and matched locally,
// so no indicator ever leaves the box.
package enrich

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Verdicts, worst first.
const (
	Malicious  = "malicious"
	Suspicious = "suspicious"
	Info       = "info"
)

// VerdictRank orders verdicts for sorting: higher is worse, 0 is none.
func VerdictRank(v string) int {
	switch v {
	case Malicious:
		return 3
	case Suspicious:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Feed is one downloadable list.
type Feed struct {
	Name string `json:"name"`
	// URL may contain {ENV_VAR}, filled from the environment when fetching
	// (for keys such as {ABUSECH_AUTH_KEY}). A feed whose variable is unset is
	// skipped. A path with no scheme is a local file, copied as is.
	URL string `json:"url"`
	// Kind is what the list holds: ip, domain, or asn (the iptoasn table).
	Kind string `json:"kind"`
	// Format: plain (one IP, CIDR or domain per line, # or ; comments),
	// hosts (a hosts file), url (one URL per line; its host counts),
	// spamhaus (Spamhaus DROP JSON lines), iptoasn (ip2asn TSV, gzipped).
	Format   string        `json:"format"`
	Verdict  string        `json:"verdict"`
	Interval time.Duration `json:"interval"`
	About    string        `json:"about,omitempty"`
}

// Provider is the name enrichment rows carry for this feed.
func (f Feed) Provider() string { return "feed:" + f.Name }

// File is where the feed is saved in dir.
func (f Feed) File(dir string) string {
	ext := ".txt"
	if f.Format == "iptoasn" {
		ext = ".tsv.gz"
	}
	return filepath.Join(dir, f.Name+ext)
}

// Builtin is the default feed list: free, no account needed. abuse.ch's
// URLhaus and ThreatFox exports now need a free Auth-Key in the URL; add them
// with -feeds-file once you have one (see README.md).
var Builtin = []Feed{
	{Name: "feodo", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Kind: "ip", Format: "plain",
		Verdict: Malicious, Interval: time.Hour, About: "abuse.ch Feodo Tracker: botnet C2 servers"},
	{Name: "spamhaus-drop", URL: "https://www.spamhaus.org/drop/drop_v4.json", Kind: "ip", Format: "spamhaus",
		Verdict: Malicious, Interval: 12 * time.Hour, About: "Spamhaus DROP: hijacked and criminal netblocks (IPv4)"},
	{Name: "spamhaus-drop6", URL: "https://www.spamhaus.org/drop/drop_v6.json", Kind: "ip", Format: "spamhaus",
		Verdict: Malicious, Interval: 12 * time.Hour, About: "Spamhaus DROP: hijacked and criminal netblocks (IPv6)"},
	{Name: "hagezi-tif", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
		Kind: "domain", Format: "plain", Verdict: Malicious, Interval: 12 * time.Hour,
		About: "HaGeZi Threat Intelligence Feeds: malware, phishing and scam domains (medium)"},
	{Name: "firehol1", URL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		Kind: "ip", Format: "plain", Verdict: Suspicious, Interval: 6 * time.Hour,
		About: "FireHOL level 1: attack sources, aggregated"},
	{Name: "hagezi-tif-ips", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt",
		Kind: "ip", Format: "plain", Verdict: Suspicious, Interval: 12 * time.Hour,
		About: "HaGeZi Threat Intelligence Feeds: IPs"},
	{Name: "tor-exits", URL: "https://check.torproject.org/torbulkexitlist", Kind: "ip", Format: "plain",
		Verdict: Suspicious, Interval: time.Hour, About: "Tor exit nodes"},
	{Name: "openphish", URL: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
		Kind: "domain", Format: "url", Verdict: Suspicious, Interval: 6 * time.Hour,
		About: "OpenPhish: hosts serving phishing URLs (can include shared hosts)"},
	{Name: "stevenblack", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Kind: "domain",
		Format: "hosts", Verdict: Info, Interval: 24 * time.Hour, About: "StevenBlack hosts: ads, trackers, malware"},
	{Name: "iptoasn", URL: "https://iptoasn.com/data/ip2asn-combined.tsv.gz", Kind: "asn", Format: "iptoasn",
		Interval: 24 * time.Hour, About: "iptoasn.com: IP ranges to ASN, owner and country"},
}

// LoadFeeds returns the built-in feeds minus disabled ones, plus any from
// extraFile (a JSON array of Feed, intervals as Go durations like "6h").
func LoadFeeds(extraFile string, disable []string) ([]Feed, error) {
	var out []Feed
	for _, f := range Builtin {
		if !slices.Contains(disable, f.Name) {
			out = append(out, f)
		}
	}
	if extraFile == "" {
		return out, nil
	}
	b, err := os.ReadFile(extraFile)
	if err != nil {
		return nil, err
	}
	var extra []struct {
		Feed
		Interval string `json:"interval"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return nil, fmt.Errorf("%s: %w", extraFile, err)
	}
	for _, e := range extra {
		f := e.Feed
		if e.Interval != "" {
			if f.Interval, err = time.ParseDuration(e.Interval); err != nil {
				return nil, fmt.Errorf("%s: feed %s: %w", extraFile, f.Name, err)
			}
		}
		if err := f.check(); err != nil {
			return nil, fmt.Errorf("%s: %w", extraFile, err)
		}
		if i := slices.IndexFunc(out, func(o Feed) bool { return o.Name == f.Name }); i >= 0 {
			out[i] = f // an extra feed with a built-in name replaces it
		} else {
			out = append(out, f)
		}
	}
	return out, nil
}

func (f *Feed) check() error {
	if f.Name == "" || strings.ContainsAny(f.Name, `/\ `) || f.URL == "" {
		return fmt.Errorf("feed %q needs a plain name and a url", f.Name)
	}
	switch f.Format {
	case "plain", "hosts", "url", "spamhaus", "iptoasn":
	default:
		return fmt.Errorf("feed %s: unknown format %q (plain|hosts|url|spamhaus|iptoasn)", f.Name, f.Format)
	}
	if f.Format != "iptoasn" && VerdictRank(f.Verdict) == 0 {
		return fmt.Errorf("feed %s: verdict must be malicious, suspicious or info", f.Name)
	}
	if f.Kind == "" {
		f.Kind = "ip"
	}
	if f.Interval <= 0 {
		f.Interval = 24 * time.Hour
	}
	return nil
}

// List is a parsed feed, ready to match against.
type List struct {
	Feed
	Version string // sha256 of the file
	Entries int

	addrs   map[netip.Addr]string
	nets    map[int]map[netip.Prefix]string // by prefix length
	bits    []int                           // lengths present, longest first
	domains map[string]string
}

// LoadList reads and parses a saved feed file.
func LoadList(f Feed, path string) (*List, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseList(f, b)
}

// ParseList parses a feed's contents.
func ParseList(f Feed, b []byte) (*List, error) {
	sum := sha256.Sum256(b)
	l := &List{Feed: f, Version: hex.EncodeToString(sum[:8]), addrs: map[netip.Addr]string{},
		nets: map[int]map[netip.Prefix]string{}, domains: map[string]string{}}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		switch f.Format {
		case "plain":
			if i := strings.IndexAny(line, "#;"); i >= 0 {
				line = line[:i]
			}
			if fs := strings.Fields(line); len(fs) > 0 {
				l.add(fs[0], "")
			}
		case "hosts":
			fs := strings.Fields(line)
			if len(fs) < 2 {
				continue
			}
			for _, h := range fs[1:] {
				if h[0] == '#' {
					break
				}
				l.add(h, "")
			}
		case "url":
			u, err := url.Parse(line)
			if err == nil && u.Hostname() != "" {
				l.add(u.Hostname(), "")
			}
		case "spamhaus":
			var e struct {
				CIDR  string `json:"cidr"`
				SBLID string `json:"sblid"`
				Type  string `json:"type"`
			}
			if json.Unmarshal([]byte(line), &e) == nil && e.Type == "" {
				l.add(e.CIDR, e.SBLID)
			}
		default:
			return nil, fmt.Errorf("feed %s: format %q is not a list", f.Name, f.Format)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for b := range l.nets {
		l.bits = append(l.bits, b)
	}
	slices.Sort(l.bits)
	slices.Reverse(l.bits)
	return l, nil
}

var notListable = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"0.0.0.0": true, "ip6-localhost": true, "ip6-loopback": true,
}

func (l *List) add(s, detail string) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || notListable[s] {
		return
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return
		}
		p = p.Masked()
		if p.IsSingleIP() {
			l.addrs[p.Addr().Unmap()] = detail
		} else {
			m := l.nets[p.Bits()]
			if m == nil {
				m = map[netip.Prefix]string{}
				l.nets[p.Bits()] = m
			}
			m[p] = detail
		}
		l.Entries++
		return
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.IsUnspecified() {
			l.addrs[a.Unmap()] = detail
			l.Entries++
		}
		return
	}
	if validDomain(s) {
		l.domains[s] = detail
		l.Entries++
	}
}

func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return false
		}
	}
	return true
}

// Match says whether the list has indicator, and through what: the listed
// IP, CIDR or (parent) domain, plus the feed's detail for it.
func (l *List) Match(indicator string) (via, detail string, ok bool) {
	if a, err := netip.ParseAddr(indicator); err == nil {
		a = a.Unmap()
		if d, ok := l.addrs[a]; ok {
			return a.String(), d, true
		}
		for _, b := range l.bits {
			if b > a.BitLen() {
				continue
			}
			p, _ := a.Prefix(b)
			if d, ok := l.nets[b][p]; ok {
				return p.String(), d, true
			}
		}
		return "", "", false
	}
	d := strings.ToLower(strings.TrimSuffix(indicator, "."))
	for {
		if det, ok := l.domains[d]; ok {
			return d, det, true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return "", "", false
		}
		d = d[i+1:]
		if !strings.Contains(d, ".") {
			return "", "", false // never match on a bare TLD
		}
	}
}

// ASN is one row of the iptoasn table.
type ASN struct {
	Number  uint32 `json:"asn"`
	Owner   string `json:"as_owner"`
	Country string `json:"country"`
}

type asnRange struct {
	start, end [16]byte
	asn        uint32
	owner      uint32 // index into owners
	country    [2]byte
}

// ASNTable maps IPs to their announcing AS.
type ASNTable struct {
	Version string
	Entries int
	ranges  []asnRange
	owners  []string
}

// LoadASN reads iptoasn's ip2asn-combined.tsv.gz.
func LoadASN(path string) (*ASNTable, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseASN(b)
}

// ParseASN parses the gzipped TSV: range_start, range_end, AS_number,
// country_code, AS_description. Unrouted ranges (AS 0) are left out.
func ParseASN(b []byte) (*ASNTable, error) {
	sum := sha256.Sum256(b)
	t := &ASNTable{Version: hex.EncodeToString(sum[:8])}
	zr, err := gzip.NewReader(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("iptoasn: %w", err)
	}
	owners := map[string]uint32{}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fs := strings.SplitN(sc.Text(), "\t", 5)
		if len(fs) < 5 {
			continue
		}
		s, err1 := netip.ParseAddr(fs[0])
		e, err2 := netip.ParseAddr(fs[1])
		var n uint32
		_, err3 := fmt.Sscan(fs[2], &n)
		if err1 != nil || err2 != nil || err3 != nil || n == 0 {
			continue
		}
		oi, ok := owners[fs[4]]
		if !ok {
			oi = uint32(len(t.owners))
			owners[fs[4]] = oi
			t.owners = append(t.owners, fs[4])
		}
		var cc [2]byte
		copy(cc[:], fs[3])
		t.ranges = append(t.ranges, asnRange{start: s.As16(), end: e.As16(), asn: n, owner: oi, country: cc})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("iptoasn: %w", err)
	}
	if err := zr.Close(); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("iptoasn: %w", err)
	}
	slices.SortFunc(t.ranges, func(a, b asnRange) int { return compare16(a.start, b.start) })
	t.Entries = len(t.ranges)
	return t, nil
}

func compare16(a, b [16]byte) int {
	for i := range a {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return 0
}

// Lookup finds the AS announcing ip.
func (t *ASNTable) Lookup(ip string) (ASN, bool) {
	a, err := netip.ParseAddr(ip)
	if t == nil || err != nil {
		return ASN{}, false
	}
	k := a.Unmap().As16() // IPv4 as ::ffff:a.b.c.d, the same as the table
	i, _ := slices.BinarySearchFunc(t.ranges, k, func(r asnRange, k [16]byte) int {
		if compare16(r.start, k) <= 0 {
			return -1
		}
		return 1
	})
	if i == 0 {
		return ASN{}, false
	}
	r := t.ranges[i-1]
	if compare16(k, r.end) > 0 {
		return ASN{}, false
	}
	cc := strings.TrimRight(string(r.country[:]), "\x00")
	return ASN{Number: r.asn, Owner: t.owners[r.owner], Country: cc}, true
}
