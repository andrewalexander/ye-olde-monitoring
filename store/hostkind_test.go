package store_test

import (
	"fmt"
	"testing"

	"dnscount/hit"
	"dnscount/store"
)

var hostCases = map[string]string{
	"":                         "",
	"jellyfin.example.com":     "name",
	"Jellyfin.Example.com:443": "name",
	"203.0.113.9":              "ip",
	"203.0.113.9:8096":         "ip",
	"[2001:db8::1]:443":        "ip",
	"[2001:db8::1]":            "ip",
	"1.2.3.4.nip.io":           "name",
	"localhost":                "name",
}

func TestHostKind(t *testing.T) {
	for host, want := range hostCases {
		if got := store.HostKind(host); got != want {
			t.Errorf("HostKind(%q) = %q, want %q", host, got, want)
		}
	}
}

// The SQL used for filtering and counting agrees with HostKind.
func TestHostKindSQL(t *testing.T) {
	st := open(t)
	var hits []hit.Hit
	want := map[string]int{}
	i := 0
	for host, kind := range hostCases {
		i++
		hits = append(hits, hit.Hit{Hash: fmt.Sprint(i), TS: now, Site: "jf", Source: "caddy", ClientIP: "203.0.113.50", Host: host, Status: 200})
		want[kind]++
	}
	if _, err := st.InsertHits(hits); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"ip", "name"} {
		got, err := st.Hits(store.HitFilter{HostKind: kind})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != want[kind] {
			t.Errorf("host_kind=%s: %d hits, want %d", kind, len(got), want[kind])
		}
		for _, h := range got {
			if store.HostKind(h.Host) != kind {
				t.Errorf("host_kind=%s returned %q", kind, h.Host)
			}
		}
	}
	if _, err := st.Hits(store.HitFilter{HostKind: "both"}); err == nil {
		t.Error("bad host_kind accepted")
	}
}
