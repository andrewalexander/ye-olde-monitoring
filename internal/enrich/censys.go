package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Censys answers in depth about hosts (services, software, certificates,
// DNS names, and on some tiers labels, threats and a reputation score) and
// about web properties (a hostname on a port). Every result costs a credit.
// Paths, media types and fields are from Censys's generated Platform SDK
// (censys-platform 0.16.7). With no organization ID, requests use the
// account's free wallet.
type Censys struct {
	Base, Token string // Base default https://api.platform.censys.io
	http        httpCaller
	bulkRefused bool // the bulk host endpoint isn't allowed on this account
}

const (
	censysHostType = "application/vnd.censys.api.v3.host.v1+json"
	censysWebType  = "application/vnd.censys.api.v3.webproperty.v1+json"
	censysBatch    = 100
)

func NewCensys(base, token string) *Censys {
	if base == "" {
		base = "https://api.platform.censys.io"
	}
	// Free and Starter accounts may only have one request in flight.
	return &Censys{Base: base, Token: token, http: httpCaller{Provider: "censys", MinGap: time.Second}}
}

func (*Censys) Name() string             { return "censys" }
func (*Censys) Handles(kind string) bool { return kind == "ip" || kind == "domain" }
func (*Censys) BatchSize() int           { return censysBatch }

func (p *Censys) request(method, path, accept string, body []byte) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		var r *bytes.Reader
		if body != nil {
			r = bytes.NewReader(body)
		} else {
			r = bytes.NewReader(nil)
		}
		req, err := http.NewRequest(method, p.Base+path, r)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Accept", accept)
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
		}
		return req, err
	}
}

// Lookup asks about addresses in one bulk request (falling back to one at
// a time if the account can't use bulk) and about domains one at a time, as
// web properties on port 443.
func (p *Censys) Lookup(ctx context.Context, inds []string) ([]Answer, int, error) {
	var ips, domains []string
	for _, ind := range inds {
		if _, err := netip.ParseAddr(ind); err == nil {
			ips = append(ips, ind)
		} else {
			domains = append(domains, ind)
		}
	}
	var out []Answer
	units := 0
	if len(ips) > 0 {
		a, n, err := p.hosts(ctx, ips)
		out, units = append(out, a...), units+n
		if err != nil {
			return out, units, err
		}
	}
	for _, d := range domains {
		a, err := p.webProperty(ctx, d)
		units++
		if err != nil {
			return out, units, err
		}
		out = append(out, a)
	}
	return out, units, nil
}

func (p *Censys) hosts(ctx context.Context, ips []string) ([]Answer, int, error) {
	if len(ips) > 1 && !p.bulkRefused {
		body, _ := json.Marshal(map[string][]string{"host_ids": ips})
		status, _, resp, err := p.http.do(ctx, p.request("POST", "/v3/global/asset/host", censysHostType, body))
		switch {
		case err == nil && status == http.StatusOK:
			var env struct {
				Result []json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(resp, &env); err != nil {
				return nil, len(ips), fmt.Errorf("censys bulk: %w", err)
			}
			found := map[string]Answer{}
			for _, raw := range env.Result {
				a, err := censysHost(raw)
				if err == nil {
					found[a.Indicator] = a
				}
			}
			var out []Answer
			for _, ip := range ips {
				if a, ok := found[ip]; ok {
					out = append(out, a)
				} else {
					out = append(out, Answer{Indicator: ip}) // Censys has nothing on it
				}
			}
			return out, len(env.Result), nil
		case IsStop(err) && (status == http.StatusForbidden || status == http.StatusMethodNotAllowed):
			// Bulk isn't on this account: ask one at a time instead.
			p.bulkRefused = true
		default:
			return nil, 1, err
		}
	}
	var out []Answer
	units := 0
	for _, ip := range ips {
		status, _, resp, err := p.http.do(ctx, p.request("GET", "/v3/global/asset/host/"+url.PathEscape(ip), censysHostType, nil))
		units++
		if err != nil {
			return out, units, err
		}
		if status == http.StatusNotFound {
			out = append(out, Answer{Indicator: ip})
			continue
		}
		var env struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(resp, &env); err != nil {
			return out, units, fmt.Errorf("censys host: %w", err)
		}
		a, err := censysHost(env.Result)
		if err != nil {
			return out, units, err
		}
		a.Indicator = ip
		out = append(out, a)
	}
	return out, units, nil
}

func (p *Censys) webProperty(ctx context.Context, domain string) (Answer, error) {
	id := domain + ":443"
	status, _, resp, err := p.http.do(ctx, p.request("GET", "/v3/global/asset/webproperty/"+url.PathEscape(id), censysWebType, nil))
	if err != nil {
		return Answer{}, err
	}
	if status == http.StatusNotFound {
		return Answer{Indicator: domain}, nil
	}
	var env struct {
		Result struct {
			Resource struct {
				Hostname string           `json:"hostname"`
				Port     int              `json:"port"`
				ScanTime string           `json:"scan_time"`
				Software []censysSoftware `json:"software"`
				Labels   []censysLabel    `json:"labels"`
				Threats  []censysThreat   `json:"threats"`
				Cert     *struct {
					Names  []string `json:"names"`
					Parsed struct {
						Subject struct {
							CommonName []string `json:"common_name"`
						} `json:"subject"`
						Issuer struct {
							Organization []string `json:"organization"`
						} `json:"issuer"`
					} `json:"parsed"`
				} `json:"cert"`
			} `json:"resource"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &env); err != nil {
		return Answer{}, fmt.Errorf("censys web property: %w", err)
	}
	r := env.Result.Resource
	facts := map[string]any{"port": r.Port, "software": softwareNames(r.Software), "labels": labelNames(r.Labels),
		"threats": threatNames(r.Threats), "scan_time": r.ScanTime}
	if r.Cert != nil {
		facts["cert_names"] = r.Cert.Names
		if len(r.Cert.Names) == 0 {
			facts["cert_names"] = r.Cert.Parsed.Subject.CommonName
		}
		facts["cert_issuer"] = strings.Join(r.Cert.Parsed.Issuer.Organization, ", ")
	}
	return Answer{Indicator: domain, Found: true, Raw: resp, Facts: facts}, nil
}

type censysSoftware struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type censysLabel struct {
	Value string `json:"value"`
}

type censysThreat struct {
	Name string `json:"name"`
}

func softwareNames(s []censysSoftware) []string {
	var out []string
	for _, x := range s {
		n := strings.TrimSpace(strings.Join([]string{x.Vendor, x.Product, x.Version}, " "))
		if n != "" {
			out = append(out, strings.Join(strings.Fields(n), " "))
		}
	}
	return out
}

func labelNames(l []censysLabel) []string {
	var out []string
	for _, x := range l {
		if x.Value != "" {
			out = append(out, x.Value)
		}
	}
	return out
}

func threatNames(t []censysThreat) []string {
	var out []string
	for _, x := range t {
		if x.Name != "" {
			out = append(out, x.Name)
		}
	}
	return out
}

// censysHost summarises one host asset: {"resource": Host, "extensions": {...}}.
func censysHost(raw json.RawMessage) (Answer, error) {
	var a struct {
		Resource struct {
			IP       string `json:"ip"`
			Services []struct {
				Port      int              `json:"port"`
				Protocol  string           `json:"protocol"`
				Transport string           `json:"transport_protocol"`
				Software  []censysSoftware `json:"software"`
				Threats   []censysThreat   `json:"threats"`
				Vulns     []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"services"`
			AS *struct {
				ASN  int    `json:"asn"`
				Name string `json:"name"`
			} `json:"autonomous_system"`
			Location *struct {
				Country string `json:"country"`
				City    string `json:"city"`
			} `json:"location"`
			DNS *struct {
				Names []string `json:"names"`
			} `json:"dns"`
			Labels     []censysLabel `json:"labels"`
			Reputation *struct {
				Label string  `json:"label"`
				Score float64 `json:"score"`
			} `json:"reputation"`
			GreyNoise *struct {
				Classification string `json:"classification"`
				Actor          string `json:"actor"`
			} `json:"greynoise"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return Answer{}, fmt.Errorf("censys host: %w", err)
	}
	r := a.Resource
	type svc struct {
		Port     int      `json:"port"`
		Protocol string   `json:"protocol"`
		Software []string `json:"software,omitempty"`
	}
	var services []svc
	var threats, vulns []string
	for _, s := range r.Services {
		services = append(services, svc{s.Port, s.Protocol, softwareNames(s.Software)})
		threats = append(threats, threatNames(s.Threats)...)
		for _, v := range s.Vulns {
			if v.ID != "" {
				vulns = append(vulns, v.ID)
			}
		}
	}
	facts := map[string]any{"services": services, "labels": labelNames(r.Labels), "threats": threats, "vulns": vulns}
	if r.AS != nil {
		facts["asn"], facts["as_name"] = r.AS.ASN, r.AS.Name
	}
	if r.Location != nil {
		facts["country"], facts["city"] = r.Location.Country, r.Location.City
	}
	if r.DNS != nil {
		facts["dns_names"] = r.DNS.Names
	}
	if r.Reputation != nil && r.Reputation.Label != "" {
		facts["reputation"] = r.Reputation.Label
	}
	if r.GreyNoise != nil && r.GreyNoise.Classification != "" {
		facts["greynoise"] = strings.TrimSpace(r.GreyNoise.Classification + " " + r.GreyNoise.Actor)
	}
	return Answer{Indicator: r.IP, Found: true, Raw: raw, Facts: facts}, nil
}
