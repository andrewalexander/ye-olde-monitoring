// Package lan reads where LAN devices are: DHCP leases and the router's
// neighbour table, as ingest.Sighting records. (UniFi's client events are
// read by ingest/ids, which owns the CEF format.)
package lan

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"dnscount/ingest"
)

// DHCP parses dnsmasq's lease acknowledgements:
//
//	dnsmasq-dhcp[3058110]: DHCPACK(br0) 192.168.1.230 02:00:00:00:00:0b Mac
//
// The hostname is optional. Every other DHCP line is skipped: only an ACK
// means the device has the address.
type DHCP struct{}

func (DHCP) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	if err != nil || h.Prog != "dnsmasq-dhcp" {
		return ingest.Record{}, ingest.ErrSkip
	}
	f := strings.Fields(h.Msg)
	if len(f) < 3 || !strings.HasPrefix(f[0], "DHCPACK(") || !strings.HasSuffix(f[0], ")") {
		return ingest.Record{}, ingest.ErrSkip
	}
	s := &ingest.Sighting{TS: h.TS, Iface: f[0][len("DHCPACK(") : len(f[0])-1], Event: "dhcpack", Source: "dnsmasq-dhcp"}
	if err := SetAddr(s, f[1], f[2]); err != nil {
		return ingest.Record{}, err
	}
	if len(f) > 3 {
		s.Hostname = strings.Join(f[3:], " ")
	}
	return ingest.Record{Seen: s}, nil
}

// Neighbours parses the lines scripts/unifi-neighbors.sh logs from the
// router's IPv4 and IPv6 neighbour tables:
//
//	dnscount-neigh: ip=2606:4700:4700::5 mac=02:00:00:00:00:05 dev=br0 state=REACHABLE
//
// They're what names IPv6 devices: DHCP never sees their addresses, but the
// MAC links them to a DHCP or UniFi name.
type Neighbours struct{}

func (Neighbours) ParseLine(line string, now time.Time) (ingest.Record, error) {
	h, err := ingest.ParseHeader(line, now)
	if err != nil || h.Prog != "dnscount-neigh" {
		return ingest.Record{}, ingest.ErrSkip
	}
	kv := map[string]string{}
	for _, f := range strings.Fields(h.Msg) {
		if k, v, ok := strings.Cut(f, "="); ok {
			kv[k] = v
		}
	}
	if kv["ip"] == "" && kv["mac"] == "" {
		return ingest.Record{}, ingest.ErrSkip // its own start-up chatter
	}
	s := &ingest.Sighting{TS: h.TS, Iface: kv["dev"], Event: "neighbour", Source: "router-neigh"}
	if err := SetAddr(s, kv["ip"], kv["mac"]); err != nil {
		return ingest.Record{}, err
	}
	return ingest.Record{Seen: s}, nil
}

// SetAddr checks and normalises an address and MAC into a sighting.
func SetAddr(s *ingest.Sighting, ip, mac string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return errors.New("sighting without a valid IP")
	}
	m, err := net.ParseMAC(mac)
	if err != nil || len(m) != 6 {
		return errors.New("sighting without a valid MAC")
	}
	s.IP, s.MAC = a.Unmap().String(), m.String()
	return nil
}
