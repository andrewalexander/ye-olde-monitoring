package enrich

import (
	"net/netip"
	"strings"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// PublicIP says whether ip is a routable internet address: not private,
// CGNAT, loopback, link-local, multicast or unspecified. LAN devices with
// global IPv6 addresses pass this; callers also exclude known LAN clients.
func PublicIP(ip string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return a, false
	}
	a = a.Unmap()
	ok := a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
	return a, ok
}

var internalSuffixes = []string{".lan", ".local", ".home.arpa", ".arpa", ".internal", ".localdomain", ".home", ".corp"}

// PublicDomain normalises d and says whether it's an internet name worth
// matching: not single-label, not a reverse-DNS name, not a LAN suffix.
func PublicDomain(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if !validDomain(d) {
		return d, false
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(d, s) || d == s[1:] {
			return d, false
		}
	}
	return d, true
}
