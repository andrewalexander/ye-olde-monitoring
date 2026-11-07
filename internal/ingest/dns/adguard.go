package dns

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/enrich"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

// AdGuard parses AdGuard Home's querylog.json (one JSON object per line).
// Each line is both a lookup and its outcome.
type AdGuard struct{}

type adguardLine struct {
	T        time.Time `json:"T"`
	QH       string    `json:"QH"`
	QT       string    `json:"QT"`
	IP       string    `json:"IP"`
	Upstream string    `json:"Upstream"`
	Cached   bool      `json:"Cached"`
	Result   struct {
		IsFiltered bool `json:"IsFiltered"`
	} `json:"Result"`
}

func (AdGuard) ParseLine(line string, _ time.Time) (ingest.Record, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return ingest.Record{}, ingest.ErrSkip
	}
	var l adguardLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		return ingest.Record{}, err
	}
	if l.QH == "" || l.T.IsZero() {
		return ingest.Record{}, errors.New("missing QH or T")
	}
	ip, err := netip.ParseAddr(l.IP)
	if err != nil {
		return ingest.Record{}, errors.New("IP: " + err.Error())
	}
	domain := enrich.NormDomain(l.QH)
	status := "reply"
	switch {
	case l.Result.IsFiltered:
		status = "blocked"
	case l.Cached:
		status = "cached"
	}
	return ingest.Record{
		Query: &ingest.DNSQuery{TS: l.T, ClientIP: ip.String(), Domain: domain, QType: strings.ToUpper(l.QT), Source: "adguard"},
		Reply: &ingest.DNSReply{TS: l.T, Domain: domain, Answer: l.Upstream, Status: status, Source: "adguard"},
	}, nil
}
