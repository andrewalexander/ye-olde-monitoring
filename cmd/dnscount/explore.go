package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dnscount/enrich"
	"dnscount/explore"
)

func defaultEnrichDB(db, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return filepath.Join(filepath.Dir(db), "explore.db")
}

func defaultFeedsDir(db, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return filepath.Join(filepath.Dir(db), "feeds")
}

// feedFlags are shared by explore, enrich and feeds.
type feedFlags struct {
	dir, extra, disable *string
}

func addFeedFlags(fs *flag.FlagSet) feedFlags {
	return feedFlags{
		dir:     fs.String("feeds-dir", "", "where feed files are saved (default: feeds/ next to -db)"),
		extra:   fs.String("feeds-file", "", "JSON file of extra feeds: [{name, url, kind, format, verdict, interval}]"),
		disable: fs.String("feeds-disable", "", "comma-separated built-in feeds to leave out"),
	}
}

func (f feedFlags) load() ([]enrich.Feed, error) {
	var off []string
	if *f.disable != "" {
		off = strings.Split(*f.disable, ",")
	}
	return enrich.LoadFeeds(*f.extra, off)
}

// exploreCmd serves the LAN table explorer from a read-only view of the
// live database.
func exploreCmd(args []string) error {
	fs := flag.NewFlagSet("explore", flag.ExitOnError)
	db := dbFlag(fs)
	enrichDB := fs.String("enrich-db", "", "the explorer's own database (default: explore.db next to -db)")
	addr := fs.String("addr", "127.0.0.1:8090", "where the UI and API listen")
	timeout := fs.Duration("query-timeout", 10*time.Second, "per-request query deadline")
	maxConns := fs.Int("max-conns", 4, "most queries running at once")
	matchEvery := fs.Duration("match-every", 10*time.Minute, "how often new indicators are indexed and matched")
	window := fs.Duration("window", 90*24*time.Hour, "how far back a changed list re-checks indicators")
	adminURL := fs.String("admin-url", "http://127.0.0.1:8081", "the live admin API, for breaker stats (empty: skip)")
	units := fs.String("units", "dnscount-serve,dnscount-syslog,dnscount-caddy-log,dnscount-fail2ban,dnscount-explore",
		"systemd units whose cgroup CPU, memory and pressure the Health view shows")
	cgroups := fs.String("cgroup-root", "/sys/fs/cgroup/system.slice", "where the units' cgroups are")
	ff := addFeedFlags(fs)
	fs.Parse(args)
	feeds, err := ff.load()
	if err != nil {
		return err
	}
	x, err := explore.Open(explore.Config{
		DB: *db, EnrichDB: defaultEnrichDB(*db, *enrichDB), FeedsDir: defaultFeedsDir(*db, *ff.dir), Feeds: feeds,
		QueryTimeout: *timeout, MaxConns: *maxConns, MatchEvery: *matchEvery, Window: *window, AdminURL: *adminURL,
		Sampler: &explore.Sampler{ProcRoot: "/proc", CgroupRoot: *cgroups, Units: strings.Split(*units, ",")},
	})
	if err != nil {
		return err
	}
	defer x.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("explorer on http://%s (read-only view of %s)", *addr, *db)
	return x.Run(ctx, *addr)
}

// enrichCmd runs one pass of what the explorer does in the background:
// reload changed feeds (reconciling them), index new rows, match.
func enrichCmd(args []string) error {
	fs := flag.NewFlagSet("enrich", flag.ExitOnError)
	db := dbFlag(fs)
	enrichDB := fs.String("enrich-db", "", "the explorer's database (default: explore.db next to -db)")
	full := fs.Bool("full", false, "reconcile every list, even unchanged ones")
	all := fs.Bool("all", false, "with -full: re-check every indicator ever seen, not just the last 90 days")
	ff := addFeedFlags(fs)
	fs.Parse(args)
	feeds, err := ff.load()
	if err != nil {
		return err
	}
	window := 90 * 24 * time.Hour
	if *all {
		window = 100 * 365 * 24 * time.Hour
	}
	x, err := explore.Open(explore.Config{DB: *db, EnrichDB: defaultEnrichDB(*db, *enrichDB),
		FeedsDir: defaultFeedsDir(*db, *ff.dir), Feeds: feeds, Window: window, ForceReconcile: *full})
	if err != nil {
		return err
	}
	defer x.Close()
	return x.Tick(context.Background())
}

// feedsCmd downloads the feeds that are due. It needs the network and
// opens no database.
func feedsCmd(args []string) error {
	if len(args) == 0 || (args[0] != "update" && args[0] != "list") {
		return fmt.Errorf("usage: dnscount feeds update|list [-feeds-dir d] [-feeds-file f] [-feeds-disable a,b] [-force]")
	}
	fs := flag.NewFlagSet("feeds "+args[0], flag.ExitOnError)
	db := dbFlag(fs)
	force := fs.Bool("force", false, "fetch every feed, even ones not due yet")
	ff := addFeedFlags(fs)
	fs.Parse(args[1:])
	feeds, err := ff.load()
	if err != nil {
		return err
	}
	dir := defaultFeedsDir(*db, *ff.dir)
	if args[0] == "list" {
		st, err := enrich.ReadState(dir)
		if err != nil {
			return err
		}
		w := table()
		fmt.Fprintln(w, "FEED\tKIND\tVERDICT\tEVERY\tENTRIES\tLAST OK\tSTATUS")
		for _, f := range feeds {
			s := st[f.Name]
			last, status, n := "never", "", 0
			if s != nil {
				n = s.Entries
				if !s.LastOK.IsZero() {
					last = localTime(s.LastOK)
				}
				status = s.Skipped + s.LastError
			}
			if s.Stale(f, time.Now()) {
				status = strings.TrimSpace("STALE " + status)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", f.Name, f.Kind, f.Verdict, f.Interval, n, last, status)
		}
		return w.Flush()
	}
	x := &enrich.Fetcher{Dir: dir, Force: *force, Log: log.Printf}
	changed, err := x.Update(context.Background(), feeds)
	log.Printf("%d feed(s) changed", len(changed))
	return err
}
