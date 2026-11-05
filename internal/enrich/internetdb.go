package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// InternetDB is Shodan's free, keyless per-address lookup: open ports,
// hostnames, software (CPEs), known CVEs and tags. Free for non-commercial
// use; https://internetdb.shodan.io/<ip>.
type InternetDB struct {
	Base string // default https://internetdb.shodan.io
	http httpCaller
}

func NewInternetDB(base string) *InternetDB {
	if base == "" {
		base = "https://internetdb.shodan.io"
	}
	return &InternetDB{Base: base, http: httpCaller{Provider: "internetdb", MinGap: time.Second}}
}

func (*InternetDB) Name() string             { return "internetdb" }
func (*InternetDB) Handles(kind string) bool { return kind == "ip" }
func (*InternetDB) BatchSize() int           { return 1 }

func (p *InternetDB) Lookup(ctx context.Context, inds []string) ([]Answer, int, error) {
	if len(inds) != 1 {
		return nil, 0, fmt.Errorf("internetdb: one address per request")
	}
	ip := inds[0]
	status, _, body, err := p.http.do(ctx, func() (*http.Request, error) {
		return http.NewRequest("GET", p.Base+"/"+url.PathEscape(ip), nil)
	})
	if err != nil {
		return nil, 1, err
	}
	if status == http.StatusNotFound {
		return []Answer{{Indicator: ip}}, 1, nil
	}
	var r struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		CPEs      []string `json:"cpes"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 1, fmt.Errorf("internetdb: %w", err)
	}
	return []Answer{{Indicator: ip, Found: true, Raw: body, Facts: map[string]any{
		"ports": r.Ports, "hostnames": r.Hostnames, "cpes": r.CPEs, "tags": r.Tags, "vulns": r.Vulns,
	}}}, 1, nil
}
