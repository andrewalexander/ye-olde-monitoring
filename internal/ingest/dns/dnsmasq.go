// Package dns parses router DNS logs into lookups (dns_queries) and answers
// (dns_replies).
package dns

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

// Dnsmasq parses dnsmasq query logs. UniFi OS runs dnsmasq, and so does
// Pi-hole (as pihole-FTL). Lines look like:
//
//	Oct 27 12:00:01 UDM dnsmasq[123]: query[A] example.com from 192.168.1.5
//	Oct 27 12:00:01 UDM dnsmasq[123]: forwarded example.com to 1.1.1.1
//	Oct 27 12:00:01 UDM dnsmasq[123]: reply example.com is 93.184.216.34
//	Oct 27 12:00:01 UDM dnsmasq[123]: cached example.com is 93.184.216.34
//	Oct 27 12:00:01 pihole-FTL[123]: gravity blocked ads.example.com is 0.0.0.0
//
// With log-queries=extra each message is prefixed by "<serial> <ip>/<port> ".
type Dnsmasq struct{}

var (
	extraRE = regexp.MustCompile(`^\d+ [0-9A-Fa-f.:]+/\d+ `)
	queryRE = regexp.MustCompile(`^query\[([A-Za-z0-9]+)\] (\S+) from (\S+)$`)
	isRE    = regexp.MustCompile(`^(reply|cached|config|gravity blocked|exactly blocked|regex blocked|special domain|cached-stale|validation \S+|\S*/\S+) (\S+) is (.+)$`)
	fwdRE   = regexp.MustCompile(`^forwarded (\S+) to (\S+)$`)
)

func (Dnsmasq) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	if err != nil {
		return ingest.Record{}, ingest.ErrSkip
	}
	if h.Prog != "dnsmasq" && h.Prog != "pihole-FTL" {
		return ingest.Record{}, ingest.ErrSkip
	}
	msg := extraRE.ReplaceAllString(strings.TrimSpace(h.Msg), "")
	switch {
	case strings.HasPrefix(msg, "query["):
		m := queryRE.FindStringSubmatch(msg)
		if m == nil {
			return ingest.Record{}, errors.New("malformed query line")
		}
		ip, err := netip.ParseAddr(m[3])
		if err != nil {
			return ingest.Record{}, errors.New("query from non-IP " + m[3])
		}
		return ingest.Record{Query: &ingest.DNSQuery{
			TS: h.TS, ClientIP: ip.String(), Domain: ingest.NormDomain(m[2]), QType: strings.ToUpper(m[1]), Source: "dnsmasq",
		}}, nil
	case strings.HasPrefix(msg, "forwarded "):
		m := fwdRE.FindStringSubmatch(msg)
		if m == nil {
			return ingest.Record{}, errors.New("malformed forwarded line")
		}
		return ingest.Record{Reply: &ingest.DNSReply{
			TS: h.TS, Domain: ingest.NormDomain(m[1]), Answer: m[2], Status: "forwarded", Source: "dnsmasq",
		}}, nil
	}
	if m := isRE.FindStringSubmatch(msg); m != nil {
		status := m[1]
		if strings.Contains(status, "/") {
			status = "local:" + status // /etc/hosts, /run/... static entries
		}
		if status == "config" && isBlockAnswer(m[2], m[3]) {
			status = "blocked"
		}
		return ingest.Record{Reply: &ingest.DNSReply{
			TS: h.TS, Domain: ingest.NormDomain(m[2]), Answer: strings.TrimSpace(m[3]), Status: status, Source: "dnsmasq",
		}}, nil
	}
	// Startup banners, DHCP, "query" to upstream with no client, etc.
	return ingest.Record{}, ingest.ErrSkip
}

// isBlockAnswer reports whether a "config" line came from a blocklist entry
// like local=/ads.example.com/. dnsmasq answers its own bogus-priv reverse
// lookups and domain-needed plain names the same way, so those don't count.
func isBlockAnswer(domain, answer string) bool {
	if !strings.HasPrefix(answer, "NXDOMAIN") && !strings.HasPrefix(answer, "NODATA") {
		return false
	}
	return strings.Contains(domain, ".") && !strings.HasSuffix(domain, ".arpa")
}
