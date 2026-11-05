package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AbuseIPDB says whether other people report an address for abuse: a
// confidence score (0-100) and report counts. Free accounts get 1,000 checks
// a day. https://docs.abuseipdb.com/#check-endpoint
type AbuseIPDB struct {
	Base, Key string // Base default https://api.abuseipdb.com
	http      httpCaller
	exhausted bool // the API said no checks are left today
}

func NewAbuseIPDB(base, key string) *AbuseIPDB {
	if base == "" {
		base = "https://api.abuseipdb.com"
	}
	return &AbuseIPDB{Base: base, Key: key, http: httpCaller{Provider: "abuseipdb", MinGap: time.Second}}
}

func (*AbuseIPDB) Name() string             { return "abuseipdb" }
func (*AbuseIPDB) Handles(kind string) bool { return kind == "ip" }
func (*AbuseIPDB) BatchSize() int           { return 1 }

func (p *AbuseIPDB) Lookup(ctx context.Context, inds []string) ([]Answer, int, error) {
	if len(inds) != 1 {
		return nil, 0, fmt.Errorf("abuseipdb: one address per request")
	}
	if p.exhausted {
		return nil, 0, &StopError{Provider: "abuseipdb", Status: http.StatusTooManyRequests, Message: "daily limit reached (X-RateLimit-Remaining: 0)"}
	}
	ip := inds[0]
	status, hdr, body, err := p.http.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequest("GET", p.Base+"/api/v2/check?maxAgeInDays=90&ipAddress="+url.QueryEscape(ip), nil)
		if err == nil {
			req.Header.Set("Key", p.Key)
			req.Header.Set("Accept", "application/json")
		}
		return req, err
	})
	if hdr != nil && hdr.Get("X-RateLimit-Remaining") == "0" {
		p.exhausted = true
	}
	if err != nil {
		return nil, 1, err
	}
	if status == http.StatusNotFound {
		return []Answer{{Indicator: ip}}, 1, nil
	}
	var r struct {
		Data struct {
			Score        int     `json:"abuseConfidenceScore"`
			Reports      int     `json:"totalReports"`
			Users        int     `json:"numDistinctUsers"`
			LastReported *string `json:"lastReportedAt"`
			Usage        string  `json:"usageType"`
			ISP          string  `json:"isp"`
			Domain       string  `json:"domain"`
			Tor          bool    `json:"isTor"`
			Whitelisted  *bool   `json:"isWhitelisted"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 1, fmt.Errorf("abuseipdb: %w", err)
	}
	d := r.Data
	facts := map[string]any{"score": d.Score, "reports": d.Reports, "users": d.Users, "usage": d.Usage,
		"isp": d.ISP, "domain": d.Domain, "tor": d.Tor}
	if d.LastReported != nil {
		facts["last_reported"] = *d.LastReported
	}
	if d.Whitelisted != nil {
		facts["whitelisted"] = *d.Whitelisted
	}
	// AbuseIPDB answers every public address; "found" means someone has
	// reported it.
	return []Answer{{Indicator: ip, Found: d.Reports > 0, Raw: body, Facts: facts}}, 1, nil
}
