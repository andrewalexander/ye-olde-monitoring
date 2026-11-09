// Command dnscount is a dumb simple hit counter and request/DNS logger.
// Run it with no arguments for the list of commands (usage, below).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/forensics"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/dns"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/f2b"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/jellyfin"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest/syslog"
	"github.com/andrewalexander/ye-olde-monitoring/internal/server"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

const usage = `usage: dnscount <command> [flags]

commands:
  serve          public counter + /ingest collector + localhost health endpoint
  syslog         receive UniFi remote syslog (DNS lookups, firewall logs)
  ingest-access  import nginx/apache "combined" or caddy JSON access logs
  ingest-dns     import dnsmasq (UniFi, Pi-hole), unifi (dnsmasq+firewall+IDS+LAN devices) or adguard logs
  ingest-bans    import fail2ban's log (journalctl -u fail2ban) to check bans held
  ingest-auth    import refused logins from an app's log (journalctl -u jellyfin)
  report         hits | dns | alerts | bans | flagged | trips | trip <id>
  check          run data sanity checks
  backup         write a timestamped copy of the database to a directory
  explore        LAN table explorer: a separate, read-only process (see README.md)
  feeds          update | list: download the free threat feeds and IP-to-ASN table
  enrich         one pass of matching indicators against the feeds (the explorer does this itself)

run "dnscount <command> -h" for flags. The database defaults to $DNSCOUNT_DB or ./dnscount.db.
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"serve": serve, "syslog": syslogCmd, "ingest-access": ingestAccess,
		"ingest-dns": ingestDNS, "ingest-bans": ingestBans, "ingest-auth": ingestAuth, "report": report, "check": check, "backup": backup,
		"explore": exploreCmd, "enrich": enrichCmd, "feeds": feedsCmd,
	}
	f, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := f(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "dnscount:", err)
		os.Exit(1)
	}
}

func dbFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("DNSCOUNT_DB")
	if def == "" {
		def = "dnscount.db"
	}
	return fs.String("db", def, "SQLite database path")
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	db := dbFlag(fs)
	addr := fs.String("addr", ":8080", "public listen address (counter + /ingest)")
	adminAddr := fs.String("admin-addr", "127.0.0.1:8081", "health endpoint listen address (breaker stats); keep it on localhost")
	token := fs.String("token", os.Getenv("DNSCOUNT_TOKEN"), "bearer token for /ingest (or $DNSCOUNT_TOKEN); empty disables /ingest")
	trusted := fs.String("trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For is believed")
	counterSites := fs.String("counter-sites", "", "comma-separated sites /counter.svg and /counter.txt answer for (visitors computed from hits); empty disables them")
	counterTTL := fs.Duration("counter-ttl", time.Minute, "how long a site's counter is reused before it's recomputed")
	fs.Parse(args)
	var sites []string
	for _, s := range strings.Split(*counterSites, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if !hit.ValidSite(s) {
			return fmt.Errorf("-counter-sites: %q is not [A-Za-z0-9._-]{1,64}", s)
		}
		sites = append(sites, s)
	}

	proxies, err := hit.ParsePrefixes(*trusted)
	if err != nil {
		return fmt.Errorf("-trusted-proxies: %w", err)
	}
	if host, _, _ := net.SplitHostPort(*adminAddr); !isLoopback(host) {
		log.Printf("warning: admin listener on %s has no auth and isn't on localhost", *adminAddr)
	}
	if *token == "" {
		log.Printf("no -token: /ingest will reject everything (the counter still works)")
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	rec := forensics.New(st, os.Stderr)
	defer rec.Close()
	srv := server.New(server.Config{
		Store: st, Token: *token, TrustedProxies: proxies, CounterSites: sites, CounterTTL: *counterTTL,
		OnTrip: rec.OnTrip, OnEnd: rec.OnEnd,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Ingest.Run(ctx)
	return runHTTP(ctx,
		&http.Server{Addr: *addr, Handler: srv.Public(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second},
		&http.Server{Addr: *adminAddr, Handler: srv.Admin(), ReadHeaderTimeout: 10 * time.Second},
	)
}

func runHTTP(ctx context.Context, servers ...*http.Server) error {
	errc := make(chan error, len(servers))
	for _, s := range servers {
		log.Printf("listening on %s", s.Addr)
		go func() { errc <- s.ListenAndServe() }()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(sctx)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func syslogCmd(args []string) error {
	fs := flag.NewFlagSet("syslog", flag.ExitOnError)
	db := dbFlag(fs)
	listen := fs.String("listen", "udp://:5514", "comma-separated udp://host:port and/or tcp://host:port")
	allow := fs.String("allow", "", "comma-separated IPs/CIDRs allowed to send (your router); required")
	raw := fs.String("raw", "", "directory to append every received line to (daily files)")
	perMin := fs.Int("per-minute", 60000, "max lines per source per minute")
	fs.Parse(args)

	allowed, err := hit.ParsePrefixes(*allow)
	if err != nil {
		return fmt.Errorf("-allow: %w", err)
	}
	if *raw != "" {
		if err := os.MkdirAll(*raw, 0o750); err != nil {
			return err
		}
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	rec := forensics.New(st, os.Stderr)
	defer rec.Close()
	l, err := syslog.New(syslog.Config{
		Store: st, Allow: allowed, RawDir: *raw, PerMinute: *perMin, OnTrip: rec.OnTrip, OnEnd: rec.OnEnd,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s := l.Stats()
				log.Printf("syslog: %d lines, %d records, %d skipped, %d bad, %d dropped, %d not allowed",
					s.Lines, s.Records, s.Skipped, s.Bad, s.Dropped, s.Rejected)
			}
		}
	}()
	return l.Listen(ctx, strings.Split(*listen, ","))
}

func ingestAccess(args []string) error {
	fs := flag.NewFlagSet("ingest-access", flag.ExitOnError)
	db := dbFlag(fs)
	format := fs.String("format", "combined", "combined (nginx/apache) | caddy")
	site := fs.String("site", "", "site name to record hits under (caddy defaults to the request host)")
	follow := fs.Bool("follow", false, "keep reading as the file grows (like tail -f)")
	fs.Parse(args)
	if *site != "" && !hit.ValidSite(*site) {
		return fmt.Errorf("-site must be [A-Za-z0-9._-]{1,64}")
	}
	var p ingest.LineParser
	switch *format {
	case "combined":
		p = ingest.Combined{Site: *site}
	case "caddy":
		p = ingest.Caddy{Site: *site}
	default:
		return fmt.Errorf("unknown -format %q", *format)
	}
	return runIngest(*db, p, fs.Args(), *follow, nil)
}

func ingestDNS(args []string) error {
	fs := flag.NewFlagSet("ingest-dns", flag.ExitOnError)
	db := dbFlag(fs)
	format := fs.String("format", "dnsmasq", "dnsmasq (UniFi, Pi-hole) | unifi (dnsmasq, firewall, IDS/IPS and LAN-device lines, e.g. syslog -raw files or the router's threat.log) | adguard")
	follow := fs.Bool("follow", false, "keep reading as the file grows (like tail -f)")
	fs.Parse(args)
	var p ingest.LineParser
	switch *format {
	case "dnsmasq", "pihole":
		p = dns.Dnsmasq{}
	case "unifi":
		// A raw syslog file is mostly lines no parser here wants.
		p = ingest.Unguard(syslog.UniFi())
	case "adguard":
		p = dns.AdGuard{}
	default:
		return fmt.Errorf("unknown -format %q", *format)
	}
	return runIngest(*db, p, fs.Args(), *follow, nil)
}

func ingestBans(args []string) error {
	fs := flag.NewFlagSet("ingest-bans", flag.ExitOnError)
	db := dbFlag(fs)
	ports := fs.String("jail-ports", "", `each jail's port setting, "sshd=ssh;jellyfin=80,443,8096"; jails not listed cover all ports`)
	follow := fs.Bool("follow", false, "keep reading as the input grows, writing each ban as it comes (use with journalctl -f)")
	fs.Parse(args)
	m, err := f2b.ParsePorts(*ports)
	if err != nil {
		return fmt.Errorf("-jail-ports: %w", err)
	}
	return runIngest(*db, &f2b.Fail2ban{Ports: m}, fs.Args(), *follow, nil)
}

func ingestAuth(args []string) error {
	fs := flag.NewFlagSet("ingest-auth", flag.ExitOnError)
	db := dbFlag(fs)
	format := fs.String("format", "jellyfin", "the app whose log this is: jellyfin")
	follow := fs.Bool("follow", false, "keep reading as the input grows (use with journalctl -f)")
	fs.Parse(args)
	if *format != "jellyfin" {
		return fmt.Errorf("-format must be jellyfin")
	}
	return runIngest(*db, jellyfin.Jellyfin{}, fs.Args(), *follow, nil)
}

// runIngest feeds each file ("-" is stdin) through p into the store in
// batches and prints a summary per file.
func runIngest(dbPath string, p ingest.LineParser, files []string, follow bool, tweak func(*ingest.Record)) error {
	if len(files) == 0 {
		files = []string{"-"}
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, name := range files {
		var r io.Reader = os.Stdin
		if name != "-" {
			f, err := os.Open(name)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
			if follow {
				r = &tailReader{path: name, f: f, poll: time.Second}
			}
		}
		var batch []ingest.Record
		inserted := 0
		flush := func() error {
			n, err := st.InsertRecords(batch)
			inserted += n
			batch = batch[:0]
			return err
		}
		stats, err := ingest.Run(r, p, time.Now(), func(rec ingest.Record) error {
			if tweak != nil {
				tweak(&rec)
			}
			if batch = append(batch, rec); len(batch) >= 500 || follow {
				return flush()
			}
			return nil
		})
		if ferr := flush(); err == nil {
			err = ferr
		}
		fmt.Fprintf(os.Stderr, "%s: %d lines, %d records (%d new rows), %d skipped, %d bad\n",
			name, stats.Lines, stats.Records, inserted, stats.Skipped, stats.Bad)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// tailReader turns EOF into "wait and try again" for -follow. It reopens
// the path when the file is rotated (renamed away and recreated, or
// truncated in place), so a log roller like Caddy's doesn't leave us
// reading a dead file forever.
type tailReader struct {
	path string
	f    *os.File
	poll time.Duration
}

func (t *tailReader) Read(p []byte) (int, error) {
	for {
		n, err := t.f.Read(p)
		if n > 0 || !errors.Is(err, io.EOF) {
			return n, err
		}
		if t.rotated() {
			if f, err := os.Open(t.path); err == nil {
				t.f.Close()
				t.f = f
				continue
			}
		}
		time.Sleep(t.poll)
	}
}

func (t *tailReader) rotated() bool {
	cur, err := os.Stat(t.path)
	if err != nil {
		return false // mid-rotation; the new file isn't there yet
	}
	old, err := t.f.Stat()
	if err != nil {
		return false
	}
	if !os.SameFile(cur, old) {
		return true
	}
	pos, err := t.f.Seek(0, io.SeekCurrent)
	return err == nil && cur.Size() < pos
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	db := dbFlag(fs)
	fs.Parse(args)
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	problems, err := st.Check(time.Now())
	if err != nil {
		return err
	}
	if len(problems) == 0 {
		fmt.Println("ok: no data problems found")
		return nil
	}
	for _, p := range problems {
		fmt.Println("problem:", p)
	}
	return fmt.Errorf("%d problem(s)", len(problems))
}
