package store

import (
	"strings"
	"time"
)

// Device is what's known about the LAN device at an address.
type Device struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac"`
	Name     string    `json:"name,omitempty"`     // Alias if you set one in UniFi, else Hostname
	Hostname string    `json:"hostname,omitempty"` // what the device calls itself
	Alias    string    `json:"alias,omitempty"`    // the name set in the UniFi Network app
	Network  string    `json:"network,omitempty"`
	Seen     time.Time `json:"seen"`   // the sighting that tied this address to the MAC
	Source   string    `json:"source"` // which kind of sighting that was
}

// Sighting is one row of lan_sightings.
type Sighting struct {
	TS       time.Time `json:"ts"`
	IP       string    `json:"ip,omitempty"`
	MAC      string    `json:"mac"`
	Hostname string    `json:"hostname,omitempty"`
	Alias    string    `json:"alias,omitempty"`
	Network  string    `json:"network,omitempty"`
	Iface    string    `json:"iface,omitempty"`
	Event    string    `json:"event"`
	Source   string    `json:"source"`
}

// deviceName picks the name to show. UniFi gives a device with no alias of
// its own a default one, "hostname xx:yy" (the MAC's last two bytes); that
// isn't a name anyone chose, so the hostname wins over it.
func deviceName(hostname, alias, mac string) string {
	a := strings.TrimSpace(alias)
	if a == "" || a == hostname {
		return hostname
	}
	if hostname != "" && len(mac) >= 5 && a == hostname+" "+mac[len(mac)-5:] {
		return hostname
	}
	return a
}

// Devices names LAN addresses as of `at` (zero: as of now): each address's
// latest sighting at or before then gives its MAC, and that MAC's latest
// names give its name. That's how an IPv6 address the router's neighbour
// table tied to a MAC gets the name DHCP or UniFi gave the same MAC.
func (s *Store) Devices(ips []string, at time.Time) (map[string]Device, error) {
	out := map[string]Device{}
	until := "9999"
	if !at.IsZero() {
		until = fmtTime(at)
	}
	var macs []string
	for start := 0; start < len(ips); start += 400 {
		chunk := ips[start:min(start+400, len(ips))]
		args := []any{until}
		for _, ip := range chunk {
			args = append(args, ip)
		}
		rows, err := s.query(`SELECT ip, mac, ts, source FROM (
				SELECT ip, mac, ts, source, row_number() OVER (PARTITION BY ip ORDER BY ts DESC, id DESC) AS rn
				FROM lan_sightings WHERE ts <= ? AND ip IN (`+placeholders(len(chunk))+`)
			) WHERE rn = 1`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var d Device
			var ts string
			if err := rows.Scan(&d.IP, &d.MAC, &ts, &d.Source); err != nil {
				rows.Close()
				return nil, err
			}
			d.Seen = parseTime(ts)
			out[d.IP] = d
			macs = append(macs, d.MAC)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	names, err := s.macNames(macs, until)
	if err != nil {
		return nil, err
	}
	for ip, d := range out {
		n := names[d.MAC]
		d.Hostname, d.Alias, d.Network = n.hostname, n.alias, n.network
		d.Name = deviceName(n.hostname, n.alias, d.MAC)
		out[ip] = d
	}
	return out, nil
}

type macName struct{ hostname, alias, network string }

// macNames is each MAC's latest hostname, alias and network up to `until`,
// each from whichever sighting last had one.
func (s *Store) macNames(macs []string, until string) (map[string]macName, error) {
	out := map[string]macName{}
	seen := map[string]bool{}
	var uniq []string
	for _, m := range macs {
		if !seen[m] {
			seen[m] = true
			uniq = append(uniq, m)
		}
	}
	for start := 0; start < len(uniq); start += 400 {
		chunk := uniq[start:min(start+400, len(uniq))]
		args := []any{until}
		for _, m := range chunk {
			args = append(args, m)
		}
		for _, col := range []string{"hostname", "alias", "network"} {
			rows, err := s.query(`SELECT mac, `+col+` FROM (
					SELECT mac, `+col+`, row_number() OVER (PARTITION BY mac ORDER BY ts DESC, id DESC) AS rn
					FROM lan_sightings WHERE ts <= ? AND `+col+` != '' AND mac IN (`+placeholders(len(chunk))+`)
				) WHERE rn = 1`, args...)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var mac, v string
				if err := rows.Scan(&mac, &v); err != nil {
					rows.Close()
					return nil, err
				}
				n := out[mac]
				switch col {
				case "hostname":
					n.hostname = v
				case "alias":
					n.alias = v
				default:
					n.network = v
				}
				out[mac] = n
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// DeviceSightings lists the sightings of an address and of every MAC seen
// at it, newest first: how a device's addresses and names changed.
func (s *Store) DeviceSightings(ip string, limit int) ([]Sighting, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.query(`SELECT ts, ip, mac, hostname, alias, network, iface, event, source FROM lan_sightings
		WHERE ip = ?1 OR mac IN (SELECT DISTINCT mac FROM lan_sightings WHERE ip = ?1)
		ORDER BY ts DESC, id DESC LIMIT ?2`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sighting
	for rows.Next() {
		var v Sighting
		var ts string
		if err := rows.Scan(&ts, &v.IP, &v.MAC, &v.Hostname, &v.Alias, &v.Network, &v.Iface, &v.Event, &v.Source); err != nil {
			return nil, err
		}
		v.TS = parseTime(ts)
		out = append(out, v)
	}
	return out, rows.Err()
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }
