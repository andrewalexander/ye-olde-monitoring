package enrich

import (
	"net/netip"
	"strings"
)

// Gate decides what may be sent to a queried provider. Every lookup tells
// the provider what we're interested in, so nothing describing our own
// network ever leaves: not private or special addresses, not any address a
// LAN device has used, not internal names, and not our own domains.
type Gate struct {
	// LAN is every address seen as a LAN device: used the router's DNS, or
	// appeared in DHCP, UniFi client events or the neighbour table. It must
	// be loaded; a nil LAN refuses everything (fail closed).
	LAN map[string]bool
	// Own are domains (and their subdomains) never to look up: ours.
	Own []string
}

// Allow says whether indicator may be sent, and if not, why.
func (g *Gate) Allow(indicator string) (bool, string) {
	if g == nil || g.LAN == nil {
		return false, "LAN addresses not loaded"
	}
	if a, err := netip.ParseAddr(indicator); err == nil {
		a = a.Unmap()
		if _, ok := PublicIP(a.String()); !ok {
			return false, "not a public address"
		}
		if s, ok := SpecialPurpose(a.String()); ok {
			return false, "special-purpose address (" + s.Name + ")"
		}
		if g.LAN[a.String()] {
			return false, "a LAN device"
		}
		return true, ""
	}
	d, ok := PublicDomain(indicator)
	if !ok {
		return false, "not a public name"
	}
	if s, ok := SpecialDomain(d); ok {
		return false, "special-use name (" + s.Name + ")"
	}
	for _, own := range g.Own {
		own = NormDomain(own)
		if own != "" && (d == own || strings.HasSuffix(d, "."+own)) {
			return false, "one of our own names (" + own + ")"
		}
	}
	return true, ""
}
