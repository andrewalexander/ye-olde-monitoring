package enrich

import "net/netip"

// Special is an entry from IANA's special-purpose address registries
// (RFC 6890), or a special-use name.
type Special struct {
	Name string `json:"name"`
	RFC  string `json:"rfc"`
	Note string `json:"note,omitempty"`
	// Reserved: never a real internet host. A feed listing it (FireHOL
	// lists every reserved range) says nothing about it, so such matches
	// are shown but set no verdict. Translation prefixes (NAT64, Teredo,
	// 6to4) carry real hosts, so they're context only.
	Reserved bool `json:"reserved"`
}

type specialRange struct {
	prefix netip.Prefix
	Special
}

// Documentation ranges are context only: real traffic never uses them, and
// tests use them as stand-ins for public addresses.
var specialRanges = func() []specialRange {
	rows := []struct {
		cidr, name, rfc, note string
		reserved              bool
	}{
		{"192.0.0.0/24", "IETF protocol assignments", "RFC 6890", "", true},
		{"192.0.0.8/32", "IPv4 dummy address", "RFC 7600", "", true},
		{"192.0.0.9/32", "Port Control Protocol anycast", "RFC 7723", "", true},
		{"192.0.0.10/32", "TURN anycast", "RFC 8155", "", true},
		{"192.0.0.170/31", "NAT64/DNS64 discovery", "RFC 7050",
			"the answer to ipv4only.arpa: devices look it up to detect NAT64 when they join a network", true},
		{"192.31.196.0/24", "AS112 (IPv4)", "RFC 7535", "sinks stray reverse lookups for private addresses", true},
		{"192.52.193.0/24", "AMT relay anycast", "RFC 7450", "", true},
		{"192.175.48.0/24", "AS112 direct delegation", "RFC 7534", "", true},
		{"198.18.0.0/15", "Benchmarking", "RFC 2544", "", true},
		{"240.0.0.0/4", "Reserved (class E)", "RFC 1112", "", true},
		{"192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC 5737", "never in real traffic", false},
		{"198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC 5737", "never in real traffic", false},
		{"203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC 5737", "never in real traffic", false},
		{"64:ff9b::/96", "NAT64 well-known prefix", "RFC 6052", "an IPv4 host reached through NAT64", false},
		{"64:ff9b:1::/48", "NAT64 local-use prefix", "RFC 8215", "", false},
		{"100::/64", "Discard-only", "RFC 6666", "", true},
		{"2001::/23", "IETF protocol assignments", "RFC 2928", "", true},
		{"2001::/32", "Teredo", "RFC 4380", "an IPv4 host tunnelled over Teredo", false},
		{"2001:2::/48", "Benchmarking (IPv6)", "RFC 5180", "", true},
		{"2001:db8::/32", "Documentation (IPv6)", "RFC 3849", "never in real traffic", false},
		{"2002::/16", "6to4", "RFC 3056", "an IPv4 host tunnelled over 6to4", false},
		{"3fff::/20", "Documentation (IPv6)", "RFC 9637", "never in real traffic", false},
		{"5f00::/16", "SRv6 SIDs", "RFC 9602", "", true},
	}
	out := make([]specialRange, len(rows))
	for i, r := range rows {
		out[i] = specialRange{netip.MustParsePrefix(r.cidr), Special{Name: r.name, RFC: r.rfc, Note: r.note, Reserved: r.reserved}}
	}
	return out
}()

// SpecialPurpose finds the most specific special-purpose range holding ip.
func SpecialPurpose(ip string) (Special, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return Special{}, false
	}
	a = a.Unmap()
	best := -1
	for i, r := range specialRanges {
		if r.prefix.Contains(a) && (best < 0 || r.prefix.Bits() > specialRanges[best].prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return Special{}, false
	}
	return specialRanges[best].Special, true
}

var specialNames = map[string]Special{
	"ipv4only.arpa": {Name: "NAT64/DNS64 discovery", RFC: "RFC 7050",
		Note: "devices look it up to detect NAT64 when they join a network; it resolves to 192.0.0.170 and .171", Reserved: true},
}

// SpecialDomain says whether d is a special-use name with a known purpose.
func SpecialDomain(d string) (Special, bool) {
	s, ok := specialNames[NormDomain(d)]
	return s, ok
}

// SpecialFor looks up either kind of indicator.
func SpecialFor(indicator string) (Special, bool) {
	if s, ok := SpecialPurpose(indicator); ok {
		return s, true
	}
	return SpecialDomain(indicator)
}

// Reserved says whether a feed match on indicator should be ignored for its
// verdict.
func Reserved(indicator string) bool {
	s, ok := SpecialFor(indicator)
	return ok && s.Reserved
}

// VerdictReserved is the verdict a reserved special-purpose indicator gets,
// whatever lists it's on: not a real host, so never flagged.
const VerdictReserved = "reserved"
