package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"dnscount/store"
)

const reportUsage = `usage:
  dnscount report hits  [-top ip|path|ua|site|host|status|method|referer] [-site s] [-ip x] [-since 24h] [-limit n]
  dnscount report dns   -domain example.com | -client 192.168.1.5 | -top domain|client  [-since 7d]
  dnscount report trips [-since 24h] [-ip x] [-breaker name]
  dnscount report trip  <id>
`

func report(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, reportUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("report "+args[0], flag.ExitOnError)
	db := dbFlag(fs)
	since := fs.String("since", "", "only since this long ago (24h, 7d) or this time")
	limit := fs.Int("limit", 50, "max rows")
	var run func(st *store.Store, since time.Time) error

	switch args[0] {
	case "hits":
		top := fs.String("top", "", "group by this column instead of listing hits")
		site := fs.String("site", "", "only this site")
		ip := fs.String("ip", "", "only this client IP")
		run = func(st *store.Store, since time.Time) error {
			if *top != "" {
				kvs, err := st.TopHits(*top, *site, since, *limit)
				if err != nil {
					return err
				}
				return printKVs(*top, kvs)
			}
			hits, err := st.Hits(store.HitFilter{Site: *site, IP: *ip, Since: since, Limit: *limit})
			if err != nil {
				return err
			}
			w := table()
			fmt.Fprintln(w, "TIME\tSITE\tSOURCE\tCLIENT\tSTATUS\tMETHOD\tPATH\tUSER AGENT")
			for _, h := range hits {
				path := h.Path
				if h.Query != "" {
					path += "?" + h.Query
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", localTime(h.TS), h.Site, h.Source, h.ClientIP,
					h.Status, h.Method, trunc(path, 60), trunc(h.UserAgent, 50))
			}
			w.Flush()
			return printTripCount(st, *ip)
		}
	case "dns":
		domain := fs.String("domain", "", "which clients looked up this domain (and its subdomains)")
		client := fs.String("client", "", "which domains this client looked up")
		top := fs.String("top", "", "domain|client: busiest domains or clients")
		run = func(st *store.Store, since time.Time) error {
			switch {
			case *domain != "":
				rows, err := st.DNSByDomain(*domain, since)
				if err != nil {
					return err
				}
				fmt.Printf("lookups of %s:\n", *domain)
				w := table()
				fmt.Fprintln(w, "CLIENT\tNAME\tLOOKUPS\tFIRST\tLAST")
				for _, r := range rows {
					fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", r.ClientIP, r.ClientName, r.Count, localTime(r.First), localTime(r.Last))
				}
				w.Flush()
				conns, err := st.ConnsForDomain(*domain, since)
				if err != nil {
					return err
				}
				return printConns("firewall-logged connections to its answers", conns)
			case *client != "":
				rows, err := st.DNSByClient(*client, since, *limit)
				if err != nil {
					return err
				}
				fmt.Printf("lookups by %s:\n", *client)
				w := table()
				fmt.Fprintln(w, "DOMAIN\tLOOKUPS\tFIRST\tLAST")
				for _, r := range rows {
					fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", r.Domain, r.Count, localTime(r.First), localTime(r.Last))
				}
				w.Flush()
				conns, err := st.ConnsForClient(*client, since)
				if err != nil {
					return err
				}
				if err := printConns("firewall-logged connections", conns); err != nil {
					return err
				}
				return printTripCount(st, *client)
			case *top != "":
				kvs, err := st.DNSTop(*top, since, *limit)
				if err != nil {
					return err
				}
				return printKVs(*top, kvs)
			}
			return fmt.Errorf("report dns needs -domain, -client or -top")
		}
	case "trips":
		ip := fs.String("ip", "", "only trips by this key/IP")
		brk := fs.String("breaker", "", "only this breaker (counter|ingest|syslog|syslog-not-allowed)")
		run = func(st *store.Store, since time.Time) error {
			trips, err := st.Trips(store.TripFilter{Since: since, Key: *ip, Breaker: *brk, Limit: *limit})
			if err != nil {
				return err
			}
			w := table()
			fmt.Fprintln(w, "ID\tTRIPPED\tBREAKER\tWHO\tREASON\tEVENTS\tBAD\tSUPPRESSED\tENDED")
			for _, t := range trips {
				ended := "still cooling down"
				if !t.EndedAt.IsZero() {
					ended = localTime(t.EndedAt)
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", t.ID, localTime(t.TrippedAt), t.Breaker, t.Key,
					t.Reason, t.WindowEvents, t.WindowBad, t.Suppressed, ended)
			}
			return w.Flush()
		}
	case "trip":
		if len(args) < 2 {
			return fmt.Errorf("report trip <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("trip id: %w", err)
		}
		args = args[1:] // let flags follow the id
		run = func(st *store.Store, _ time.Time) error {
			t, err := st.Trip(id)
			if err != nil {
				return fmt.Errorf("trip %d: %w", id, err)
			}
			detail := t.Detail
			t.Detail = nil
			head, _ := json.MarshalIndent(t, "", "  ")
			fmt.Printf("trip:\n%s\n", head)
			var pretty bytes.Buffer
			if json.Indent(&pretty, detail, "", "  ") == nil {
				fmt.Printf("detail at the time of the trip:\n%s\n", pretty.Bytes())
			}
			h, err := st.IPHistory(t.Key)
			if err != nil {
				return err
			}
			now, _ := json.MarshalIndent(h, "", "  ")
			fmt.Printf("what we know about %s now:\n%s\n", t.Key, now)
			return nil
		}
	default:
		fmt.Fprint(os.Stderr, reportUsage)
		os.Exit(2)
	}
	fs.Parse(args[1:])
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := store.ParseSince(*since, time.Now())
	if err != nil {
		return err
	}
	return run(st, s)
}

func table() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0) }

func printKVs(by string, kvs []store.KV) error {
	w := table()
	fmt.Fprintf(w, "%s\tCOUNT\n", by)
	for _, kv := range kvs {
		fmt.Fprintf(w, "%s\t%d\n", trunc(kv.Key, 100), kv.Count)
	}
	return w.Flush()
}

func printConns(title string, conns []store.ConnStat) error {
	if len(conns) == 0 {
		fmt.Printf("%s: none\n", title)
		return nil
	}
	fmt.Printf("%s:\n", title)
	w := table()
	fmt.Fprintln(w, "CLIENT\tDST\tPORT\tPROTO\tACTION\tCOUNT\tFIRST\tLAST")
	for _, c := range conns {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%s\t%s\n", c.ClientIP, c.DstIP, c.DstPort, c.Proto, c.Action,
			c.Count, localTime(c.First), localTime(c.Last))
	}
	return w.Flush()
}

func printTripCount(st *store.Store, ip string) error {
	if ip == "" {
		return nil
	}
	n, err := st.TripCount(ip)
	if err != nil {
		return err
	}
	fmt.Printf("breaker trips: %d", n)
	if n > 0 {
		fmt.Printf(" (dnscount report trips -ip %s)", ip)
	}
	fmt.Println()
	return nil
}

func localTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
