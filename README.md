# ye-olde-monitoring

_What started with a simple old school page counter plus a desire to self host a media server resulted in .. this_

---
Putting a service on the Internet (e.g. [ye-olde-jellyfin](https://github.com/andrewalexander/ye-olde-jellyfin)) means scans within minutes/seconds. These can be scary. 

This set of packages gives some visibility. Probably reinvents a ton of wheels, but was a great way for me to get re-familiarized with this kind of data and flows. 

One Go binary, one SQLite file, and a simple table based ui on the LAN

- **Every request** to your sites. From Caddy's access log, Go middleware, or through imported nginx/Apache logs - `ingest-access -follow`
- **Every DNS lookup and logged connection** on your network, from a UniFi router's remote syslog. `ingest-dns` for one shot or `dnscount-syslog` stream
- **IDS/IPS alerts** from the router, and **fail2ban bans**, each checked afterwards to confirm the ban held. from `ingest-syslog` stream
- **Threat feeds**, matched locally against all of the above, plus optional per-address lookups (InternetDB, AbuseIPDB, Censys). `enrich -provider censys -dry-run`
- **A LAN-only explorer**: sortable tables that join it all, from an IP to its hits, bans, alerts, lists and the devices that talked to it. 

It also has a NixOS module for it: `services.dnscount`; and so does the companion fail2ban guard, `services.dnscount.guard`, which bans scanners based on what Caddy logs. 

There's also an old-school visitor counter too, because that's what we set out to build initially 😅

<img width="1350" height="619" alt="image" src="https://github.com/user-attachments/assets/61434c13-7b48-4f13-ae79-6713dea69627" />

## Install

### binary:

```sh
go build -o dnscount ./cmd/dnscount
go test ./...
```

### server: NixOS

```nix
inputs.monitoring.url = "github:andrewalexander/ye-olde-monitoring";
# modules = [ monitoring.nixosModules.default { services.dnscount.enable = true; } ];
```

Units run as their own user. Enabling the service also installs `dnscount-admin`, which runs reports as that user against the service database. 

Without flakes, import `nix/module.nix` and set `services.dnscount.package = pkgs.callPackage ./nix/package.nix { }`.

```nix
services.dnscount = {
  enable = true;
  environmentFile = "/var/lib/secrets/dnscount.env";   # DNSCOUNT_TOKEN=..., root-only, outside the store
  caddyLog.enable = true;                              # record every request Caddy serves
  syslog = { enable = true; address = "<this-host>"; allow = [ "<router-ip>" ]; };  # opens 5514/udp to the router only
  explore.enable = true;                               # the table explorer, on 127.0.0.1:8090
  lookups.enable = true;                               # InternetDB and AbuseIPDB hourly, Censys by hand
  guard = { enable = true; exempt = [ "<lan>" ]; };    # fail2ban over Caddy's log
};
# Each Caddy site writes the log that dnscount and the guard read:
services.caddy.virtualHosts."example.com".logFormat = config.services.dnscount.caddyLog.format;
```
#### Test

`nix build .#checks.x86_64-linux.module` and `.guard` boot VMs (KVM needed) that test the module and the guard.

### server: systemd + static binary

```sh
make deploy HOST=you@homeserver            # ARCH=arm64 for a Pi / ARM box
```

This runs the tests, cross-compiles a static Linux binary, copies it with `deploy/` to the host, and runs `deploy/install.sh` under sudo on the target server. Running it again upgrades.

The installer creates a `dnscount` system user (in the `caddy` group), and writes `/etc/dnscount/dnscount.env` with a random `/ingest` token on first install only. 

It also installs hardened units: `dnscount-serve`, `dnscount-caddy-log`, `dnscount-explore` (on 127.0.0.1:8090), an hourly `dnscount-feeds.timer`, and a daily `dnscount-backup.timer` that keeps 7 copies. 

For Caddy, add the marked blocks from `deploy/Caddyfile.example` to each site, and its LAN-only block for the explorer.

```sh
alias dnscount='sudo -u dnscount env DNSCOUNT_DB=/var/lib/dnscount/dnscount.db dnscount'
```

### Locally (Docker / Tilt)

```sh
make up        # or: docker compose up --build -d, or: tilt up
make smoke     # counter, Caddy log tailing, middleware -> /ingest, breaker trip, sanity check
make down      # stop and delete the local data
```

http://localhost:8000 is a retro test page behind Caddy. It has the counter, links that make hits, a button that floods `/ingest` with garbage, and a live table of recent hits. http://localhost:8001 is `examples/app`, which ships hits through the Go middleware. Run reports with `docker compose exec dnscount dnscount report hits -top ip`.

## What it records

### Requests

**From Caddy** (or any access log like Apache or nginx using `combined`):

```sh
dnscount ingest-access -format caddy -follow /var/log/caddy/access.log
dnscount ingest-access -format combined -site www /var/log/nginx/access.log
```

**From Go code:** wrap your http handler; TrustedProxies is still experimental to auto reject requests that do not include an X-Forwarded-For from a trusted host

```go
sink := middleware.NewRemoteSink("http://collector:8080/ingest", token)
defer sink.Close()
http.ListenAndServe(":8000", middleware.Wrap(mux, sink, middleware.Options{
	Site:           "blog",
	TrustedProxies: proxies, // only these peers' X-Forwarded-For is believed
	SkipPaths:      []string{"/healthz"},
}))
```

`middleware` and `hit` are the importable packages. Everything else is `internal/`. 

Sinks never block the app: a hit is dropped when the buffer is full, and a sink stops trying for 30s after 5 failed writes in a row. There's a full example in `examples/app`.

Values of credential-looking query parameters (`api_key`, `token`, `X-Emby-Token`, ...) are stored as `REDACTED`, in the query and the referer, whichever way a hit comes in. Lines that aren't a normal request (TLS sent to an HTTP port, scanner junk) are kept, with the raw request as the path.

### DNS lookups and firewall logs (UniFi)

Includes pihole or adguard-like dns filtering using public block lists regularly updated. 

1. `dnscount syslog -listen udp://:5514 -allow <router-ip> -raw ./raw` (or `services.dnscount.syslog`).
2. In UniFi Network, go to Remote Logging (syslog/SIEM) and point it at that host, port 5514. Turn on security events too, so IDS/IPS alerts arrive as CEF.
3. Turn on DNS query logging on the router. Read the caveats at the top of each script first:
   - `ssh root@<router> 'sh -s' < scripts/unifi-dns-blocking.sh` logs, blocks with regularly updated lists, and survives reboots. Turn off UniFi's Ad Blocking: its CoreDNS hides the real client.
   - `ssh root@<router> 'sh -s' < scripts/unifi-enable-dns-log.sh` only logs, and is wiped on reboot.
4. `ssh root@<router> 'sh -s' < scripts/unifi-neighbors.sh` logs the neighbour table, so IPv6 devices get names.
5. Firewall lines only appear for rules that have logging turned on.

`-raw` keeps every received line in daily files. Re-ingest with `dnscount ingest-dns -format unifi raw/*.log`: rows dedup on a line hash, so re-imports add nothing. This is useful as parsers are added and we want to backfill data we otherwise could have included when it came in the first time.

Also supported: `-format dnsmasq` (Pi-hole too) and `-format adguard`. Syslog timestamps carry no timezone, so keep this host's zone the same as the router's. Other ways to get logs off the router are written up in `internal/ingest/syslog/syslog.go`.

**LAN devices are named** from DHCP leases, UniFi client events (the alias you set, else the hostname), and the neighbour table for ipv6. 

A lookup is named by the device at that address at the time; the result is stored and history is kept, meaning you can see every IP that MAC address has ever had in history. 

### IDS/IPS alerts

The router's CEF (Common Event Format) events give us the name of the LAN device (`dst_name`/`dst_mac`), its `direction`, and the `policy` that fired.

```sh
dnscount report alerts -since 24h                  # newest first, with how many requests each source made to us
dnscount report alerts -top signature -since 7d
dnscount report alerts -action allowed -since 24h  # detected but let through: worth a look
ssh <router> cat /var/log/ulog/threat.log | dnscount ingest-dns -format unifi -   # import older ones
```

### Bans (the guard)

`services.dnscount.guard` runs fail2ban, banning IPs based on rules from Caddy's JSON access log or dnscount's journal for breaker trips. Each Caddy line's `client_ip` is the real visitor. Only the path is matched, so a search term can't trip a jail when a user is using the website normally.

| Jail | Trigger | Ban |
|---|---|---|
| `caddy-probe` | 2 requests in an hour for paths no real client asks for (`.env`, `.git`, `.php`, `wp-`, `aws.json`, `*.log`, traversal… see `guard.probePaths`) | 1 day |
| `caddy-404` | 20 other 404s in 10 minutes, outside the path prefixes in `guard.notFoundIgnore` | 1 hour |
| `caddy-401` | 20 401s in 10 minutes (token guessing; an app's own log often has no address for these) | 1 hour |
| `dnscount-trip` | one trip of a breaker in `guard.tripBreakers` (default: counter, ingest) | 1 hour |
| `guard.extraJails` | your app's own, such as a failed-login jail | yours |

Each new ban of the same IP lasts twice as long as the last, up to a week, across all jails. `guard.exempt` networks are never banned (like LAN addresses). 

`dnscount-fail2ban` reads the bans from fail2ban's journal. `report bans` pairs each ban with its unban, and counts requests that got through **during** the ban on a port the jail blocks. Any of those means the ban leaked.

```sh
dnscount report bans -since 7d                    # LEAK marks a ban that didn't hold
sudo fail2ban-client status caddy-probe           # who is banned now
sudo fail2ban-client set caddy-probe banip <ip>   # by hand (1 day, escalating)
```

### Refused logins

Where Jellyfin runs, `dnscount-jellyfin-auth` follows its journal and records each refused login (`Authentication request for <user> has been denied (IP: …)`): the address and the name tried. Its first start backfills whatever the journal still holds. The explorer counts them per inbound address and lists them on the address's page. The names stay on the LAN; lookups only ever see the address.

### Counter

- `GET /counter.svg?site=blog` counts one visit and returns the image; `&noinc=1` returns it without counting.
- `GET /counter.txt?site=blog` returns the plain number.
- `GET /counter.js` inserts the image where its `<script data-site=...>` tag sits.

Each IP gets 30 counts per minute (`-counter-limit`). Requests over the limit still get the image but aren't counted.

## Reporting and Exploring 

### CLI Reports

```sh
dnscount report dns -domain example.com      # who looked it (and subdomains) up, and connections to what it resolved to
dnscount report dns -client 192.168.1.5      # what that client looked up
dnscount report dns -top domain -since 24h
dnscount report dns -new domain              # first seen in the last 24h (or -since)
dnscount report hits -top ip -site blog -since 7d
dnscount report hits -ip 198.51.100.4
dnscount report hits -top path -status 404   # -status takes a code or a class like 4xx
dnscount report hits -bottom ua,method,path,ip -since 7d  # ranks by the first field; the rest label its rows
dnscount report trips -since 24h             # circuit-breaker trips; `report trip 12` for one
dnscount report flagged -since 7d            # everything on a threat list, in or out
dnscount check                               # data sanity checks
```

**An example daily routine** for a service you are monitoring:
1. `report alerts -action allowed -since 24h`: did the IPS let anything through?
2. `report hits -status 404 -top ip -since 24h`: is there a scanner the jails missed? Ban it, and add any new paths to `guard.probePaths`.
3. `report bans -since 7d`: who have we blocked? have they managed to accrue any hits since the ban?
4. `report hits -new ip -site <site> -since 24h`: who is new?

### API 

The explorer and CLI use the same data you can get via the JSON api

If you `GET /api`, there is a plain-text reference for every endpoint (from `internal/explore/api.txt`). `dnscount serve`'s localhost admin listener (`127.0.0.1:8081`) only answers `/api/health`: the live breaker stats.

### The explorer

<img width="1229" height="593" alt="image" src="https://github.com/user-attachments/assets/0d7fbbb7-e949-470d-af71-798de1b98a04" />

`dnscount explore` (`services.dnscount.explore`) is a separate process that reads the live database read-only and serves a UI on localhost. Put it behind a LAN-only proxy. It has no password.

| View | What it's for |
|---|---|
| **Overview** | Health at a glance, indicators indexed, how many are flagged |
| **Flagged** | Every listed IP or domain seen: **in** (it reached us), **out** (the LAN reached it) or **both**, with the LAN devices involved |
| **Inbound IPs** | Everyone who hit us, got banned, raised an alert, tripped a breaker or had a login refused, with AS, country and lists; worst first |
| **Domains** | What the LAN looked up: listed names, names that resolved to listed addresses, new names |
| **LAN clients** | Each device and how many flagged names it looked up |
| **Hits, Bans, Alerts, Trips** | The raw records, newest first, each with what's known about its address; a trip opens everything recorded when it tripped |
| **IP and domain pages** | Everything about one indicator: lists (including ones it dropped off), hits, bans, alerts, who asked. A LAN address's page also has its device, sightings and what it looked up |
| **Health** | WAL size, pressure, per-unit CPU and memory, query times, feed freshness, row counts, data checks, breakers |

Its API is documented in `internal/explore/api.txt`.

### Threat feeds

<img width="1466" height="358" alt="image" src="https://github.com/user-attachments/assets/1d849087-cbd6-41f1-87c1-e0e669778df6" />

These are free, and need no account. `dnscount-feeds` downloads them hourly, each one only when it's due, and matches them on the box. Nothing about your traffic leaves the box.

| Feed | Kind | Verdict | Every |
|---|---|---|---|
| abuse.ch Feodo Tracker (botnet C2) | IP | malicious | 1h |
| Spamhaus DROP v4 and v6 | CIDR | malicious | 12h |
| HaGeZi Threat Intelligence Feeds, medium | domain | malicious | 12h |
| FireHOL level 1 | CIDR | suspicious | 6h |
| HaGeZi TIF IPs | IP | suspicious | 12h |
| Tor exits | IP | suspicious | 1h |
| OpenPhish | domain | suspicious | 6h |
| StevenBlack hosts (ads, trackers) | domain | info | 24h |
| iptoasn.com (AS, owner, country) | ranges | – | 24h |

When a list changes, every indicator seen in the last 90 days is re-checked against it, and entries that left the list are kept as "removed". Reserved addresses (RFC 6890) get the verdict **reserved** and are never flagged.

- **Add your own lists:** `explore.feeds.extra.mine = { url = "/etc/dnscount/bad-ips.txt"; interval = "10m"; };`.
- **abuse.ch URLhaus/ThreatFox** need a free Auth-Key: put `ABUSECH_AUTH_KEY=<key>` in `explore.feeds.environmentFile`, and use `{ABUSECH_AUTH_KEY}` in the feed URL.
- **Check them:** `dnscount feeds list` shows each feed's age, entry count and errors.

### Outside lookups

<img width="1611" height="853" alt="Screenshot 2026-11-07 at 6 53 34 PM" src="https://github.com/user-attachments/assets/02682117-aea3-4210-8b92-dccdf0a7b0be" />

These services are asked about one address at a time, and their answers are cached. The answers are context shown next to the verdict; they never flag anything themselves.

| Service | Tells you | Runs | Default caps | Key |
|---|---|---|---|---|
| Shodan InternetDB | ports, hostnames, CVEs, tags | hourly | 500/day; re-asked after 7 days | none |
| AbuseIPDB | abuse score, reports, usage type | hourly | 800/day; 7 days | `ABUSE_IPDB_KEY` |
| Censys | services, certificates, names, labels | **only when you run it** | 100/month, 25/day; 30 days | `CENSYS_TOKEN` |

They're asked about inbound addresses that are listed, banned, alerted on, tripped a breaker or had a login refused, and about flagged domains and what they resolved to. **Never sent:** private and special-purpose addresses, any address a LAN device has used, internal names, and `lookups.neverLookup`. Every request is logged, and the caps are counted from that log.

Put the keys in `/var/lib/dnscount/lookups.env` (mode 0640, `root:dnscount`). Without them, only InternetDB runs. To spend Censys credits: run `dnscount enrich -provider censys -dry-run` first, then without `-dry-run`.

### When to add a read replica

The explorer reads the live database. In WAL mode, readers never block writers, but a long read holds back checkpoints. Revisit (with a replica, or `VACUUM INTO` snapshots) if the Health view's WAL tile goes amber (over 64 MB), or `journalctl -u dnscount-syslog -u dnscount-caddy-log | grep -i busy` finds anything.

## Auth and circuit breakers

Depending on the component, different auth and limits apply. a circuit breaker trip leads to a ban
| Endpoint | Auth | Limits |
|---|---|---|
| counter | none | 30/min per IP |
| `POST /ingest` | `Authorization: Bearer <token>` (`-token` or `$DNSCOUNT_TOKEN`) | 1 MB body, 1000 hits/batch, 600 req/min, 10 bad/min per IP |
| admin listener (`/api/health`) | none; it only listens on localhost | none |
| explorer | none; keep it LAN-only (Caddy) | per-request query deadline |
| syslog | source-IP allowlist (`-allow`, required) | 60k lines/min per source; trips if >50% of lines are malformed |

`/ingest` answers `400` for bad JSON or an invalid hit (the whole batch is rejected), `401` for a missing or wrong token, `413` when the body is too large, and `429` with `Retry-After` only once that IP has tripped the breaker.

A trip writes one row to `breaker_trips` with everything known about the client at that moment. That includes all request headers (`Authorization`/`Cookie` only as a hash and length), the body sample and parse error, the last 20 events, the rate curve, reverse DNS, and what the database already knows about the IP. A flood produces one row per trip, not one per request. Each trip also logs `breaker trip: breaker=<name> ip=<ip> reason=<reason>` to dnscount's journal, which the guard's `dnscount-trip` jail bans on.

## License

MIT
