// Package syslog receives a UniFi router's remote syslog and stores the DNS
// lookups/answers (dnsmasq lines), firewall-logged connections (kernel
// lines), IDS/IPS alerts (CEF security events), and where LAN devices are
// (DHCP leases, UniFi client events, the router's neighbour table) it carries.
//
// Setup: in UniFi Network, Settings → CyberSecure/System → Remote Logging
// (syslog / SIEM server), point it at the host running
//
//	dnscount syslog -listen udp://:5514 -allow <router-ip> -raw ./raw
//
// and turn on dnsmasq query logging (scripts/unifi-enable-dns-log.sh).
//
// Other ways to get data off the router. These are notes, not built:
//
//   - SSH pull from cron. Re-pulling the same file is harmless because rows
//     dedup on line_hash. The log path and rotation scheme need checking on
//     the device:
//     ssh root@router 'cat /var/log/daemon.log' | dnscount ingest-dns -format unifi -
//   - Offline bundles. A possible `dnscount export`/`import` of tables as
//     gzipped NDJSON or CSV to move datasets between machines. The dumbest
//     working version today:
//     sqlite3 dnscount.db "VACUUM INTO 'copy.db'"
//     and copy copy.db.
package syslog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/guard"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/dns"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/fw"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/ids"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/lan"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// MaxLine is the longest syslog line accepted; longer ones are truncated and
// counted bad.
const MaxLine = 8 * 1024

type Config struct {
	Store *store.Store
	// Allow is the source allowlist. Syslog has no auth, so this is the only
	// thing stopping anyone from writing to the database.
	Allow []netip.Prefix
	// RawDir, if set, gets every line from allowed sources appended to a
	// daily file, so nothing is lost if a parser misses something. Re-ingest
	// with `dnscount ingest-dns -format unifi`.
	RawDir      string
	RawMaxBytes int64 // per daily file
	// PerMinute is the most lines one source may send per minute.
	PerMinute     int
	Cooldown      time.Duration
	OnTrip, OnEnd func(guard.Trip)
	Now           func() time.Time
	Log           *log.Logger
}

type Stats struct {
	Lines    int64 `json:"lines"`
	Records  int64 `json:"records"`
	Skipped  int64 `json:"skipped"`
	Bad      int64 `json:"bad"`
	Dropped  int64 `json:"dropped"`
	Rejected int64 `json:"rejected_not_allowed"`
}

type Listener struct {
	cfg Config
	// Sources is per allowed source: line rate plus a malformed-ratio trip.
	Sources *guard.Breaker
	// Strangers trips on the first line from a source not on the allowlist.
	Strangers *guard.Breaker
	parser    ingest.LineParser

	mu       sync.Mutex
	dedup    *ingest.Deduper
	batch    []ingest.Record
	raw      *os.File
	rawDay   string
	rawBytes int64
	stats    Stats
}

func New(cfg Config) (*Listener, error) {
	if len(cfg.Allow) == 0 {
		return nil, errors.New("syslog: refusing to start without an allowlist (-allow <router-ip>)")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = log.Default()
	}
	if cfg.PerMinute == 0 {
		cfg.PerMinute = 60000
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 5 * time.Minute
	}
	if cfg.RawMaxBytes == 0 {
		cfg.RawMaxBytes = 512 << 20
	}
	return &Listener{
		cfg: cfg,
		Sources: guard.New(guard.Config{
			Name: "syslog", Window: time.Minute, Cooldown: cfg.Cooldown, Max: cfg.PerMinute,
			BadRatio: 0.5, MinEvents: 20, Now: cfg.Now, OnTrip: cfg.OnTrip, OnEnd: cfg.OnEnd,
		}),
		Strangers: guard.New(guard.Config{
			Name: "syslog-not-allowed", Window: time.Minute, Cooldown: 2 * cfg.Cooldown, MaxBad: 1,
			Now: cfg.Now, OnTrip: cfg.OnTrip, OnEnd: cfg.OnEnd,
		}),
		parser: ingest.Multi{dns.Dnsmasq{}, fw.IPTables{}, ids.UniFi{}, lan.DHCP{}, lan.Neighbours{}},
		dedup:  ingest.NewDeduper(),
	}, nil
}

func (l *Listener) allowed(a netip.Addr) bool { return hit.InPrefixes(a, l.cfg.Allow) }

// HandleLine processes one syslog line from src.
func (l *Listener) HandleLine(src netip.AddrPort, transport, line string) {
	line = strings.TrimRight(line, "\r\n\x00")
	if strings.TrimSpace(line) == "" {
		return
	}
	ip := src.Addr().Unmap()
	key := ip.String()
	detail := func(problem string) map[string]any {
		d := map[string]any{"source_ip": key, "source_port": src.Port(), "transport": transport,
			"line": hit.Clean(line, 2048), "line_bytes": len(line)}
		if problem != "" {
			d["problem"] = problem
		}
		return d
	}
	ev := func(problem string) guard.Event {
		sum, _ := json.Marshal(map[string]any{"port": src.Port(), "line": hit.Clean(line, 1024), "err": problem})
		return guard.Event{Data: string(sum), Trigger: detail(problem)}
	}
	l.mu.Lock()
	l.stats.Lines++
	l.mu.Unlock()

	if !l.allowed(ip) {
		l.count(func(s *Stats) { s.Rejected++ })
		l.Strangers.Bad(key, "not_allowed", ev("source not on allowlist"))
		return
	}
	oversize := len(line) > MaxLine
	if oversize {
		line = line[:MaxLine]
	}
	l.writeRaw(line)
	if !l.Sources.Allow(key, ev("")) {
		l.count(func(s *Stats) { s.Dropped++ })
		return
	}
	if oversize {
		l.count(func(s *Stats) { s.Bad++ })
		l.Sources.Bad(key, "oversize", ev(fmt.Sprintf("line over %d bytes", MaxLine)))
		return
	}
	rec, err := l.parser.ParseLine(line, l.cfg.Now())
	switch {
	case errors.Is(err, ingest.ErrSkip):
		l.count(func(s *Stats) { s.Skipped++ })
	case err != nil:
		l.count(func(s *Stats) { s.Bad++ })
		l.Sources.Bad(key, "malformed", ev(err.Error()))
	default:
		l.mu.Lock()
		rec.SetHash(l.dedup.Key(line))
		l.batch = append(l.batch, rec)
		l.stats.Records++
		full := len(l.batch) >= 200
		l.mu.Unlock()
		if full {
			l.Flush()
		}
	}
}

func (l *Listener) count(f func(*Stats)) {
	l.mu.Lock()
	f(&l.stats)
	l.mu.Unlock()
}

// Flush writes buffered records to the store.
func (l *Listener) Flush() {
	l.mu.Lock()
	batch := l.batch
	l.batch = nil
	l.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if _, err := l.cfg.Store.InsertRecords(batch); err != nil {
		l.cfg.Log.Printf("syslog: storing %d records: %v (raw lines are still in -raw if set)", len(batch), err)
	}
}

func (l *Listener) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats
}

func (l *Listener) writeRaw(line string) {
	if l.cfg.RawDir == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	day := l.cfg.Now().Format("2006-01-02")
	if day != l.rawDay {
		if l.raw != nil {
			l.raw.Close()
			l.raw = nil
		}
		f, err := os.OpenFile(filepath.Join(l.cfg.RawDir, day+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			l.cfg.Log.Printf("syslog: raw file: %v", err)
			return
		}
		fi, _ := f.Stat()
		l.raw, l.rawDay, l.rawBytes = f, day, fi.Size()
	}
	if l.raw == nil || l.rawBytes+int64(len(line))+1 > l.cfg.RawMaxBytes {
		return
	}
	n, _ := fmt.Fprintln(l.raw, line)
	l.rawBytes += int64(n)
}

// Close flushes and closes the raw file.
func (l *Listener) Close() {
	l.Flush()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.raw != nil {
		l.raw.Close()
		l.raw = nil
	}
}

// Listen serves each address ("udp://:5514", "tcp://0.0.0.0:5514") until ctx
// is done. It also runs the periodic flush and breaker sweeps.
func (l *Listener) Listen(ctx context.Context, addrs []string) error {
	errc := make(chan error, len(addrs))
	var closers []func()
	for _, a := range addrs {
		network, hostport, ok := strings.Cut(a, "://")
		if !ok {
			network, hostport = "udp", a
		}
		switch network {
		case "udp":
			pc, err := net.ListenPacket("udp", hostport)
			if err != nil {
				return err
			}
			closers = append(closers, func() { pc.Close() })
			go func() { errc <- l.serveUDP(pc) }()
		case "tcp":
			ln, err := net.Listen("tcp", hostport)
			if err != nil {
				return err
			}
			closers = append(closers, func() { ln.Close() })
			go func() { errc <- l.serveTCP(ln) }()
		default:
			return fmt.Errorf("syslog: unknown network %q (udp|tcp)", network)
		}
		l.cfg.Log.Printf("syslog: listening on %s", a)
	}
	go l.Sources.Run(ctx)
	go l.Strangers.Run(ctx)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	defer func() {
		for _, c := range closers {
			c()
		}
		l.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return err
		case <-tick.C:
			l.Flush()
		}
	}
}

func (l *Listener) serveUDP(pc net.PacketConn) error {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		src := addr.(*net.UDPAddr).AddrPort()
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			l.HandleLine(src, "udp", line)
		}
	}
}

// octetRE matches RFC 6587 octet-counted framing ("123 <30>...").
var octetRE = regexp.MustCompile(`^\d+ <`)

func (l *Listener) serveTCP(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			src, _ := netip.ParseAddrPort(c.RemoteAddr().String())
			if !l.allowed(src.Addr()) {
				l.HandleLine(src, "tcp", "(connection refused: source not on allowlist)")
				return
			}
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 0, 4096), 64*1024)
			for sc.Scan() {
				line := sc.Text()
				if octetRE.MatchString(line) {
					line = line[strings.IndexByte(line, ' ')+1:]
				}
				l.HandleLine(src, "tcp", line)
			}
		}()
	}
}
