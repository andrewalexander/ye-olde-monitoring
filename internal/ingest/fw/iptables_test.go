package fw

import (
	"errors"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

func TestNewerUniFiLines(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.Local)
	const mac = `MAC=02:00:00:00:00:01:02:00:00:00:00:02:08:00`
	cases := []struct {
		line                   string
		src, dst, action, rule string
		port                   int
	}{
		{`<13>Nov  6 00:00:01 media-router media-router [WAN_IN-RET-30005] DESCR="[WAN_IN]Allow Port Forward {Jellyfin" IN=eth3 OUT=br2 ` + mac + ` SRC=203.0.113.9 DST=192.168.1.110 LEN=40 TOS=00 PREC=0x40 TTL=54 ID=0 PROTO=TCP SPT=44922 DPT=443 SEQ=0 ACK=0 WINDOW=0 SYN URGP=0 MARK=1a0000`,
			"203.0.113.9", "192.168.1.110", "return", "WAN_IN-RET-30005", 443},
		// The old kernel-tagged form still parses.
		// This host's kernel, logging a packet fail2ban rejected (journalctl --output=short-iso).
		{`2026-11-09T10:00:00-05:00 server kernel: f2b-caddy-probe-certain: IN=enp1s0 OUT= MAC=aa:bb SRC=203.0.113.50 DST=192.168.1.110 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=51000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0`,
			"203.0.113.50", "192.168.1.110", "reject", "f2b-caddy-probe-certain", 443},
		{`<4>Oct 27 15:00:02 UDM-Pro kernel: [ 1234.5678] [WAN_LOCAL-D-2147483647] IN=eth8 OUT= MAC=cc:dd SRC=198.51.100.7 DST=192.0.2.1 LEN=40 PROTO=TCP SPT=40000 DPT=22 WINDOW=1024 SYN URGP=0`,
			"198.51.100.7", "192.0.2.1", "drop", "WAN_LOCAL-D-2147483647", 22},
	}
	for _, c := range cases {
		r, err := IPTables{}.ParseLine(c.line, now)
		if err != nil {
			t.Errorf("%s: %v", c.rule, err)
			continue
		}
		k := r.Conn
		if k == nil || k.ClientIP != c.src || k.DstIP != c.dst || k.Action != c.action || k.Rule != c.rule || k.DstPort != c.port || k.Proto != "tcp" || k.TS.IsZero() {
			t.Errorf("%s: got %+v", c.rule, k)
		}
	}
	for _, line := range []string{
		// The DNAT copy of a forwarded packet: the forwarded rule has it.
		`<13>Nov  6 00:00:01 media-router media-router [PREROUTING-DNAT-3] DESCR="PortForward DNAT [Jellyfin HTTPS]" IN=eth3 OUT= ` + mac + ` SRC=203.0.113.9 DST=192.0.2.44 LEN=40 PROTO=TCP SPT=44922 DPT=443 SYN`,
		// LAN devices talking to the router.
		`<13>Nov  6 00:00:08 media-router media-router [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0 OUT= ` + mac + ` SRC=192.168.1.30 DST=192.168.1.1 LEN=64 PROTO=TCP SPT=61889 DPT=443 SYN`,
		// Other untagged lines with brackets but no packet fields.
		`<13>Nov  6 00:00:01 media-router media-router [some-daemon] started`,
		`<6>Oct 27 15:00:04 UDM-Pro kernel: br0: port 2(eth1) entered forwarding state`,
	} {
		if _, err := (IPTables{}).ParseLine(line, now); !errors.Is(err, ingest.ErrSkip) {
			t.Errorf("%q: err = %v, want ErrSkip", line, err)
		}
	}
}
