package ingest_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/dns"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/fw"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/ids"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/lan"
)

var now = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

func run(t *testing.T, file string, p ingest.LineParser) (ingest.Stats, []ingest.Record) {
	t.Helper()
	f, err := os.Open("../testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []ingest.Record
	st, err := ingest.Run(f, p, now, func(r ingest.Record) error { recs = append(recs, r); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return st, recs
}

func TestDnsmasqFixture(t *testing.T) {
	st, recs := run(t, "dnsmasq.log", dns.Dnsmasq{})
	if want := (ingest.Stats{Lines: 17, Records: 14, Skipped: 2, Bad: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	var queries, replies int
	statuses := map[string]int{}
	for _, r := range recs {
		if r.Query != nil {
			queries++
			if r.Query.Domain != strings.ToLower(r.Query.Domain) || strings.HasSuffix(r.Query.Domain, ".") {
				t.Errorf("domain not normalized: %q", r.Query.Domain)
			}
		}
		if r.Reply != nil {
			replies++
			statuses[r.Reply.Status]++
		}
	}
	if queries != 7 || replies != 7 {
		t.Errorf("queries=%d replies=%d, want 7 and 7", queries, replies)
	}
	if statuses["cached"] != 2 || statuses["forwarded"] != 1 || statuses["blocked"] != 1 || statuses["reply"] != 3 {
		t.Errorf("statuses = %v", statuses)
	}
	q := recs[0].Query
	if q == nil || q.ClientIP != "192.168.1.5" || q.Domain != "example.com" || q.QType != "A" ||
		!q.TS.Equal(time.Date(2026, 10, 27, 12, 0, 1, 0, time.UTC)) {
		t.Errorf("first query = %+v", q)
	}
	// Identical lines in the same second are separate lookups and must get
	// separate dedup keys.
	seen := map[string]bool{}
	for _, r := range recs {
		if r.Query != nil {
			if seen[r.Query.Hash] {
				t.Errorf("duplicate hash for %+v", r.Query)
			}
			seen[r.Query.Hash] = true
		}
	}
}

func TestPiholeFixture(t *testing.T) {
	st, recs := run(t, "pihole.log", dns.Dnsmasq{})
	if st.Records != 5 || st.Bad != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if r := recs[1].Reply; r == nil || r.Status != "gravity blocked" || r.Domain != "doubleclick.net" {
		t.Errorf("blocked reply = %+v", r)
	}
	if r := recs[3].Reply; r == nil || r.Status != "local:/etc/pihole/custom.list" || r.Answer != "10.0.0.2" {
		t.Errorf("custom.list reply = %+v", r)
	}
	if q := recs[4].Query; q == nil || q.ClientIP != "10.0.0.13" || q.Domain != "example.com" {
		t.Errorf("log-queries=extra query = %+v", q)
	}
}

func TestUnifiSyslogFixture(t *testing.T) {
	st, recs := run(t, "unifi-syslog.log", ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}})
	if want := (ingest.Stats{Lines: 6, Records: 4, Skipped: 2}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	c := recs[2].Conn
	if c == nil || c.ClientIP != "192.168.1.20" || c.DstIP != "203.0.113.66" || c.DstPort != 443 ||
		c.Proto != "tcp" || c.Action != "accept" || c.Rule != "LAN_IN-A-2000" {
		t.Errorf("accept conn = %+v", c)
	}
	c = recs[3].Conn
	if c == nil || c.ClientIP != "198.51.100.7" || c.DstPort != 22 || c.Action != "drop" || c.Rule != "WAN_LOCAL-D-2147483647" {
		t.Errorf("drop conn (with uptime prefix) = %+v", c)
	}
}

// Both shapes of UniFi IDS/IPS alert: Suricata's JSON from the router's
// threat.log, and the CEF security events sent to a SIEM server.
func TestUnifiIDSFixture(t *testing.T) {
	st, recs := run(t, "unifi-ids.log", ids.UniFi{})
	// Skipped: the "Test Syslog" button and an admin login. Bad: a threat with no source.
	if want := (ingest.Stats{Lines: 8, Records: 5, Skipped: 2, Bad: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	if len(recs) != 5 {
		t.Fatalf("got %d records", len(recs))
	}
	est := time.FixedZone("", -5*3600)
	want := []ingest.IDSAlert{
		{TS: time.Date(2026, 11, 1, 23, 24, 21, 139078000, est), SrcIP: "192.168.1.10", SrcPort: 58249, DstIP: "198.51.100.20", DstPort: 56385,
			Proto: "udp", Action: "allowed", Signature: "ET P2P BitTorrent DHT ping request", SignatureID: 2008581,
			Category: "Potential Corporate Privacy Violation", Severity: 1, Source: "unifi-ids"},
		{TS: time.Date(2026, 11, 2, 21, 31, 20, 22895000, est), SrcIP: "203.0.113.5", SrcPort: 38072, DstIP: "192.168.1.10", DstPort: 443,
			Proto: "tcp", Action: "allowed", Signature: "ET DROP Dshield Block Listed Source group 1", SignatureID: 2402000,
			Category: "Misc Attack", Severity: 2, Source: "unifi-ids"},
		{SrcIP: "203.0.113.6", Action: "blocked", SignatureID: 2402000, Source: "unifi-ids"},
		{TS: time.Date(2026, 10, 27, 22, 11, 0, 0, time.UTC), SrcIP: "203.0.113.7", SrcPort: 51234, DstIP: "192.168.1.10", DstPort: 443,
			Proto: "tcp", Action: "blocked", Signature: "ET SCAN Suspicious inbound to mySQL port 3306", SignatureID: 2010937,
			Category: "Potentially Bad Traffic", Severity: 7, Source: "unifi-cef"},
		{SrcIP: "2001:db8::5", Action: "allowed", Signature: "ET INFO Suspicious UA", Category: "Misc activity", Source: "unifi-cef"},
	}
	for i, w := range want {
		a := recs[i].Alert
		if a == nil {
			t.Fatalf("record %d has no alert", i)
		}
		if a.SrcIP != w.SrcIP || a.Action != w.Action || a.Source != w.Source ||
			(w.Signature != "" && a.Signature != w.Signature) || (w.SignatureID != 0 && a.SignatureID != w.SignatureID) ||
			(w.Category != "" && a.Category != w.Category) || (w.DstPort != 0 && (a.DstIP != w.DstIP || a.DstPort != w.DstPort ||
			a.SrcPort != w.SrcPort || a.Proto != w.Proto || a.Severity != w.Severity)) ||
			(!w.TS.IsZero() && !a.TS.Equal(w.TS)) {
			t.Errorf("alert %d =\n %+v\nwant\n %+v", i, *a, w)
		}
	}
}

func TestAdGuardFixture(t *testing.T) {
	st, recs := run(t, "adguard.json", dns.AdGuard{})
	if want := (ingest.Stats{Lines: 3, Records: 2, Bad: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	if r := recs[0]; r.Query.Domain != "telemetry.example.net" || r.Reply.Status != "blocked" {
		t.Errorf("blocked = %+v %+v", r.Query, r.Reply)
	}
	if r := recs[1]; r.Query.Domain != "example.com" || r.Query.QType != "AAAA" || r.Reply.Status != "cached" {
		t.Errorf("cached = %+v %+v", r.Query, r.Reply)
	}
}

func TestCombinedFixture(t *testing.T) {
	st, recs := run(t, "access-combined.log", ingest.Combined{Site: "www"})
	if want := (ingest.Stats{Lines: 6, Records: 5, Bad: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	h := recs[0].Hit
	if h.ClientIP != "203.0.113.9" || h.Method != "GET" || h.Path != "/index.html" || h.Query != "ref=x" ||
		h.Status != 200 || h.Bytes != 512 || h.Referer != "https://google.com/" || h.Site != "www" {
		t.Errorf("first hit = %+v", h)
	}
	if !h.TS.Equal(time.Date(2026, 10, 27, 19, 0, 1, 0, time.UTC)) {
		t.Errorf("ts = %v", h.TS)
	}
	// A TLS handshake sent to a plain-HTTP port is kept, raw, as the path.
	tlsHit := recs[2].Hit
	tlsHit.Sanitize()
	if tlsHit.Method != "" || tlsHit.Status != 400 || !strings.HasPrefix(tlsHit.Path, "?") {
		t.Errorf("tls junk hit = %+v", tlsHit)
	}
	if ua := recs[4].Hit.UserAgent; ua != `Mozilla/5.0 "quoted"` {
		t.Errorf("escaped UA = %q", ua)
	}
}

func TestCaddyFixture(t *testing.T) {
	st, recs := run(t, "access-caddy.log", ingest.Caddy{})
	if want := (ingest.Stats{Lines: 3, Records: 2, Skipped: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	h := recs[0].Hit
	if h.Site != "blog.example.com" || h.Path != "/post/1" || h.Query != "utm=x" || h.UserAgent != "curl/8.0" ||
		h.TS.UnixMilli() != 1793127601500 {
		t.Errorf("caddy hit = %+v", h)
	}
	if h := recs[1].Hit; h.ClientIP != "198.51.100.4" || h.Site != "blog.example.com" || h.ForwardedFor != "198.51.100.4" {
		t.Errorf("proxied caddy hit = %+v", h)
	}
}

func TestYearRollover(t *testing.T) {
	jan := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	h, err := ingest.ParseHeader("Dec 31 23:59:59 UDM dnsmasq[1]: query[A] a.com from 10.0.0.1", jan)
	if err != nil {
		t.Fatal(err)
	}
	if h.TS.Year() != 2026 {
		t.Errorf("December line read in January got year %d, want 2026", h.TS.Year())
	}
	h, _ = ingest.ParseHeader("Jan  1 00:00:01 UDM dnsmasq[1]: x", jan)
	if h.TS.Year() != 2027 || h.TS.Day() != 1 {
		t.Errorf("same-year line got %v", h.TS)
	}
}

func TestHeaderShapes(t *testing.T) {
	for _, line := range []string{
		"Oct 27 12:00:01 UDM dnsmasq[1]: hello",
		"Oct 27 12:00:01 dnsmasq[1]: hello",
		"<30>Oct 27 12:00:01 UDM dnsmasq[1]: hello",
		"2026-10-27T12:00:01.5-07:00 UDM dnsmasq[1]: hello",
		"<30>1 2026-10-27T12:00:01Z UDM dnsmasq 1 - - hello",
		`<30>1 2026-10-27T12:00:01Z UDM dnsmasq 1 - [meta x="a b"] hello`,
	} {
		h, err := ingest.ParseHeader(line, now)
		if err != nil || h.Prog != "dnsmasq" || h.Msg != "hello" {
			t.Errorf("%q -> %+v, %v", line, h, err)
		}
	}
}

func TestWrongFormatGuard(t *testing.T) {
	junk := strings.Repeat("<html>not a log</html>\n", ingest.GuardLines+10)
	_, err := ingest.Run(strings.NewReader(junk), dns.Dnsmasq{}, now, func(ingest.Record) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "wrong -format") {
		t.Errorf("err = %v, want wrong-format guard", err)
	}
}

// A whole syslog stream is mostly other daemons' lines; Unguard reads on.
func TestUnguardReadsPastTheGuard(t *testing.T) {
	var b strings.Builder
	for range ingest.GuardLines + 10 {
		b.WriteString("<30>Nov  6 00:00:01 router ubios-udapi-server[1]: some chatter\n")
	}
	b.WriteString("<30>Oct 27 12:00:01 UDM dnsmasq[123]: query[A] example.com from 192.168.1.20\n")
	var got int
	st, err := ingest.Run(strings.NewReader(b.String()), ingest.Unguard(ingest.Multi{dns.Dnsmasq{}}), now,
		func(ingest.Record) error { got++; return nil })
	if err != nil || got != 1 || st.Skipped != ingest.GuardLines+10 {
		t.Errorf("got %d records, %+v, %v; want the one query after the chatter", got, st, err)
	}
}

func TestDeduperIsDeterministic(t *testing.T) {
	lines := []string{"a", "b", "a", "a", "<30>b"}
	keys := func() []string {
		d := ingest.NewDeduper()
		var out []string
		for _, l := range lines {
			out = append(out, d.Key(l))
		}
		return out
	}
	k1, k2 := keys(), keys()
	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatalf("keys differ between runs at %d", i)
		}
	}
	if k1[0] == k1[2] || k1[2] == k1[3] {
		t.Error("repeated line got the same key")
	}
	if k1[4] == k1[1] {
		t.Error("<PRI>b should be the second copy of b, not the first")
	}
}

// UniFi remote logging repeats the hostname, as captured from a UDR7.
func TestUniFiRepeatedHostname(t *testing.T) {
	line := "<30>Nov  1 20:54:07 Router Router dnsmasq[631808]: 3 127.0.0.1/36841 query[A] example.org from 127.0.0.1"
	h, err := ingest.ParseHeader(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if h.Host != "Router" || h.Prog != "dnsmasq" {
		t.Errorf("header = %+v", h)
	}
	r, err := dns.Dnsmasq{}.ParseLine(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if q := r.Query; q == nil || q.Domain != "example.org" || q.ClientIP != "127.0.0.1" || q.QType != "A" {
		t.Errorf("query = %+v", r.Query)
	}
	for _, junk := range []string{"Nov  1 20:54:07 a b c d: msg", "Nov  1 20:54:07 no tag here at all"} {
		if _, err := ingest.ParseHeader(junk, now); err == nil {
			t.Errorf("%q: expected an error", junk)
		}
	}
}

// Captured from dnsmasq 2.90 answering from a local=/domain/ blocklist.
func TestBlocklistAnswers(t *testing.T) {
	for _, tc := range []struct{ msg, status string }{
		{"4 127.0.0.1/34290 config ad.001zb.com is NXDOMAIN", "blocked"},
		{"5 127.0.0.1/34290 config ad.001zb.com is NODATA-IPv6", "blocked"},
		{"6 192.168.1.5/5353 config 1.168.192.in-addr.arpa is NXDOMAIN", "config"},
		{"7 192.168.1.5/5353 config printer is NXDOMAIN", "config"},
		{"8 192.168.1.5/5353 config unifi.localdomain is 192.168.1.1", "config"},
		{"9 192.168.1.5/5353 reply example.com is 93.184.216.34", "reply"},
	} {
		r, err := dns.Dnsmasq{}.ParseLine("Nov  2 02:28:30 Router Router dnsmasq[1]: "+tc.msg, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.msg, err)
		}
		if r.Reply == nil || r.Reply.Status != tc.status {
			t.Errorf("%s: reply = %+v, want status %s", tc.msg, r.Reply, tc.status)
		}
	}
}

// UniFi's CEF events name the LAN device and the direction, and often have
// no address for the LAN end. The first line is a real one, anonymised; the
// second is an outgoing event in the same scheme.
func TestUnifiCEFContext(t *testing.T) {
	st, recs := run(t, "unifi-cef.log", ids.UniFi{})
	if st.Records != 2 || st.Bad != 0 {
		t.Fatalf("stats = %+v", st)
	}
	in, out := recs[0].Alert, recs[1].Alert
	want := ingest.IDSAlert{SrcIP: "203.0.113.30", SrcPort: 52555, DstIP: "", DstPort: 443, Proto: "tcp", Action: "blocked",
		Signature: "ET DROP Dshield Block Listed Source group 1", SignatureID: 2402000, Severity: 7, Source: "unifi-cef",
		Direction: "incoming", DstName: "media-server", DstMAC: "02:00:00:00:00:02", Policy: "DShield Block List",
		TS: time.Date(2026, 11, 3, 15, 3, 25, 230000000, time.UTC)}
	got := *in
	got.Hash = ""
	if !got.TS.Equal(want.TS) {
		t.Errorf("ts = %v", got.TS)
	}
	got.TS = want.TS
	if got != want {
		t.Errorf("incoming =\n %+v\nwant\n %+v", got, want)
	}
	if out.Direction != "outgoing" || out.SrcName != "Kitchen tablet" || out.SrcMAC != "02:00:00:00:00:03" ||
		out.DstIP != "198.51.100.80" || out.DstName != "" || out.Action != "allowed" || out.Policy != "Malware" {
		t.Errorf("outgoing = %+v", *out)
	}
}

// Where LAN devices are: DHCP acks, UniFi client events and the router's
// neighbour table (scripts/unifi-neighbors.sh).
func TestLANSightings(t *testing.T) {
	st, recs := run(t, "unifi-lan.log", ingest.Multi{ids.UniFi{}, lan.DHCP{}, lan.Neighbours{}})
	// Skipped: DHCPREQUEST, "Updating leases", the admin event. Bad: the
	// neighbour line with no valid address.
	if want := (ingest.Stats{Lines: 10, Records: 6, Skipped: 3, Bad: 1}); st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
	var got []ingest.Sighting
	for _, r := range recs {
		if r.Seen == nil {
			t.Fatalf("record without a sighting: %+v", r)
		}
		s := *r.Seen
		s.Hash, s.TS = "", time.Time{}
		got = append(got, s)
	}
	want := []ingest.Sighting{
		{IP: "192.168.1.230", MAC: "02:00:00:00:00:0b", Hostname: "Mac", Iface: "br0", Event: "dhcpack", Source: "dnsmasq-dhcp"},
		{IP: "192.168.1.102", MAC: "02:00:00:00:00:0a", Iface: "br2", Event: "dhcpack", Source: "dnsmasq-dhcp"},
		{IP: "192.168.1.131", MAC: "02:00:00:00:00:0c", Hostname: "android-4f2a", Alias: "Kitchen tablet", Network: "Default",
			Event: "connected", Source: "unifi-cef"},
		{MAC: "02:00:00:00:00:0c", Alias: "Kitchen tablet", Event: "disconnected", Source: "unifi-cef"},
		{IP: "2606:4700:10::5", MAC: "02:00:00:00:00:0b", Iface: "br0", Event: "neighbour", Source: "router-neigh"},
		{IP: "2606:4700:10::7", MAC: "02:00:00:00:00:0c", Iface: "br0", Event: "neighbour", Source: "router-neigh"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sightings: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sighting %d =\n %+v\nwant\n %+v", i, got[i], want[i])
		}
	}
	if ts := recs[2].Seen.TS; !ts.Equal(time.Date(2026, 11, 3, 14, 16, 23, 890000000, time.UTC)) {
		t.Errorf("CEF sighting time = %v, want UNIFIutcTime", ts)
	}
}
