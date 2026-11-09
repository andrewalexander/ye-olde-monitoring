package syslog

import (
	"bytes"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

// The dnscount-ids jail's failregex (idsRegex in nix/guard.nix), with <HOST>
// as a capture group, so the Go line and the jail can't drift apart.
func idsRegex(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile("../../../nix/guard.nix")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`idsRegex = ''(.*)'';`).FindSubmatch(b)
	if m == nil {
		t.Fatal("idsRegex not found in nix/guard.nix")
	}
	return regexp.MustCompile(strings.Replace(string(m[1]), "<HOST>", `(\S+)`, 1))
}

func TestIDSBlockLineMatchesJail(t *testing.T) {
	re := idsRegex(t)
	alert := func(src, action, dir string) *ingest.IDSAlert {
		return &ingest.IDSAlert{SrcIP: src, Action: action, Direction: dir, SignatureID: 2035314,
			Signature: `ET USER_AGENTS Suspcious LeakIX User-Agent (l9explore) ip=10.0.0.1 "x"`}
	}
	for _, c := range []struct {
		a   *ingest.IDSAlert
		ban string // "" means no ban
	}{
		{alert("45.138.12.51", "blocked", "incoming"), "45.138.12.51"},
		{alert("2001:db8::7", "blocked", ""), "2001:db8::7"},
		{alert("::ffff:45.138.12.51", "blocked", "incoming"), "45.138.12.51"},
		{alert("45.138.12.51", "allowed", "incoming"), ""}, // the IPS let it through: not this jail's call
		{alert("172.16.0.78", "blocked", "outgoing"), ""},  // a LAN device
		{alert("192.168.1.5", "blocked", ""), ""},
		{alert("45.138.12.51", "blocked", "outgoing"), ""}, // our side started it
		{alert("not-an-ip", "blocked", "incoming"), ""},
		{nil, ""},
	} {
		line, ok := IDSBlockLine(c.a)
		got := ""
		if ok {
			// As the journal sees it: the logger's timestamp first.
			if m := re.FindStringSubmatch("2026/11/09 12:00:00 " + line); m != nil {
				got = m[1]
			}
		}
		if got != c.ban {
			t.Errorf("%+v: line %q bans %q, want %q", c.a, line, got, c.ban)
		}
	}
}

// The listener logs the line for the router's own CEF events: once for an
// incoming block, never for an alert it let through from a LAN device.
func TestListenerLogsIDSBlocks(t *testing.T) {
	l, st, _ := setup(t, "")
	var out bytes.Buffer
	l.cfg.Log = log.New(&out, "", 0)
	b, err := os.ReadFile("../../testdata/unifi-cef.log")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		l.HandleLine(router, "udp", line)
	}
	l.Flush()
	var n int
	st.DB().QueryRow(`SELECT count(*) FROM ids_alerts`).Scan(&n)
	if n != 2 {
		t.Fatalf("stored %d alerts, want 2", n)
	}
	got := strings.TrimSpace(out.String())
	if m := idsRegex(t).FindStringSubmatch(got); m == nil || m[1] != "203.0.113.30" || strings.Count(got, "\n") != 0 {
		t.Errorf("logged %q, want one ids block line for 203.0.113.30", got)
	}
}
