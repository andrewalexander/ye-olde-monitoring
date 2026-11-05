package store_test

import (
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/dns"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/fw"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/ids"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/lan"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

func seen(t *testing.T, st *store.Store, hash string, ts time.Time, ip, mac, hostname, alias, source string) {
	t.Helper()
	if _, err := st.InsertRecords([]ingest.Record{{Seen: &ingest.Sighting{Hash: hash, TS: ts, IP: ip, MAC: mac,
		Hostname: hostname, Alias: alias, Event: "test", Source: source}}}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceNames(t *testing.T) {
	st := open(t)
	if n := importFile(t, st, "unifi-lan.log", ingest.Multi{ids.UniFi{}, lan.DHCP{}, lan.Neighbours{}}); n != 6 {
		t.Fatalf("stored %d sightings, want 6", n)
	}
	t1, t2 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	// An address reused: one device, then another.
	seen(t, st, "r1", t1, "192.168.1.50", "02:00:00:00:00:d1", "old-laptop", "", "dnsmasq-dhcp")
	seen(t, st, "r2", t2, "192.168.1.50", "02:00:00:00:00:d2", "new-phone", "", "dnsmasq-dhcp")
	// UniFi's default alias ("hostname xx:yy") isn't a chosen name.
	seen(t, st, "a1", t1, "172.16.0.10", "02:00:00:00:00:0d", "media-server", "media-server 00:0d", "unifi-cef")

	dev, err := st.Devices([]string{"192.168.1.230", "2606:4700:10::5", "2606:4700:10::7",
		"192.168.1.131", "172.16.0.102", "192.168.1.50", "172.16.0.10", "192.168.1.99"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"192.168.1.230":          "Mac",            // DHCP hostname
		"2606:4700:10::5": "Mac",            // IPv6, named through the MAC DHCP saw
		"2606:4700:10::7": "Kitchen tablet", // through the MAC UniFi named
		"192.168.1.131":          "Kitchen tablet", // the alias you set beats the hostname
		"172.16.0.102":           "",               // a lease with no hostname
		"192.168.1.50":           "new-phone",      // whoever has it now
		"172.16.0.10":            "media-server",   // not "media-server 00:0d"
	} {
		d, ok := dev[ip]
		if !ok || d.Name != want {
			t.Errorf("%s: %+v, want name %q", ip, d, want)
		}
	}
	if d := dev["2606:4700:10::5"]; d.MAC != "02:00:00:00:00:0b" || d.Source != "router-neigh" || d.Hostname != "Mac" {
		t.Errorf("v6 device: %+v", d)
	}
	if d := dev["192.168.1.131"]; d.Network != "Default" || d.Hostname != "android-4f2a" {
		t.Errorf("unifi device: %+v", d)
	}
	if _, ok := dev["192.168.1.99"]; ok {
		t.Error("named an address never seen")
	}
	// As of between the two leases, the address was the old device's.
	old, _ := st.Devices([]string{"192.168.1.50"}, t1.Add(time.Hour))
	if old["192.168.1.50"].Name != "old-laptop" {
		t.Errorf("as of t1: %+v", old["192.168.1.50"])
	}

	// The history of an IPv6 address includes its MAC's DHCP lease.
	sg, err := st.DeviceSightings("2606:4700:10::5", 0)
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, s := range sg {
		sources = append(sources, s.Source+" "+s.IP)
	}
	if len(sg) != 2 || sg[0].IP == sg[1].IP {
		t.Errorf("sightings: %v", sources)
	}

	// Lookups by a v6 address come back named.
	st.InsertRecords([]ingest.Record{{Query: &ingest.DNSQuery{Hash: "q6", TS: now, ClientIP: "2606:4700:10::5",
		Domain: "example.com", Source: "t"}}})
	lk, err := st.DNSByDomain("example.com", time.Time{})
	if err != nil || len(lk) != 1 || lk[0].ClientName != "Mac" || lk[0].MAC != "02:00:00:00:00:0b" {
		t.Errorf("lookups: %+v %v", lk, err)
	}
}

// The explorer names LAN clients, and anything seen as a LAN device counts
// as LAN even if it never used the router's DNS.
func TestExplorerUsesDeviceNames(t *testing.T) {
	x := openExplorer(t)
	importFile(t, x.primary, "unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}})
	importFile(t, x.primary, "unifi-lan.log", ingest.Multi{ids.UniFi{}, lan.DHCP{}, lan.Neighbours{}})
	seen(t, x.primary, "s20", now.Add(-time.Hour), "192.168.1.20", "02:00:00:00:00:20", "desk-pc", "", "dnsmasq-dhcp")
	x.index(t)
	cl, err := x.ro.Clients(now.AddDate(0, 0, -30))
	if err != nil || len(cl) != 1 || cl[0].Name != "desk-pc" || cl[0].MAC != "02:00:00:00:00:20" {
		t.Errorf("clients: %+v %v", cl, err)
	}
	if lanDev, _ := x.ro.IsLAN("2606:4700:10::7"); !lanDev {
		t.Error("a neighbour-table address isn't LAN")
	}
	p, err := x.ro.IPProfile("2606:4700:10::7", now.AddDate(0, 0, -30), now)
	if err != nil || p.Device == nil || p.Device.Name != "Kitchen tablet" || len(p.Sightings) < 2 {
		t.Errorf("profile device: %+v sightings %d %v", p.Device, len(p.Sightings), err)
	}
}
