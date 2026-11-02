# dnscount

A dumb simple hit counter and request/DNS logger. Go + one SQLite file.

1. **Old-school visitor counter**: `<script src="https://you:8080/counter.js" data-site="blog"></script>`
2. **Who's hitting my services**: Go middleware (or imported access logs) records the IP, path, UA, status etc. for every request.
3. **Who on my network looks up what**: receives a UniFi router's remote syslog and records DNS lookups (dnsmasq) and firewall-logged connections.

```sh
go build -o dnscount ./cmd/dnscount
go test ./...
```

## Try it locally (Docker / Tilt)

```sh
make up        # or: docker compose up --build -d, or: tilt up
make smoke     # counter, Caddy log tailing, middleware -> /ingest, breaker trip, sanity check
make down      # stop and delete the local data
```

- http://localhost:8000 is a retro test page behind Caddy. It has the counter, links that make hits (404s, query strings, another site), a button that floods `/ingest` with garbage, and a live table of recent hits.
- http://localhost:8001 is `examples/app`, shipping hits through the Go middleware.
- `127.0.0.1:8081` is the admin API.
- Reports: `docker compose exec dnscount dnscount report hits -top ip`.

The stack mirrors the systemd deploy: Caddy in front, `dnscount serve`, and a second process tailing Caddy's JSON log into the same SQLite file (on a named volume).

## Deploy (systemd + static binary)

```sh
make deploy HOST=you@homeserver            # ARCH=arm64 for a Pi / ARM box
```

This runs the tests, cross-compiles a static Linux binary, copies it with `deploy/` to the host, and runs `deploy/install.sh` under sudo. Running it again upgrades. The installer:
- creates a `dnscount` system user (added to the `caddy` group)
- writes `/etc/dnscount/dnscount.env` with a random `/ingest` token, on first install only
- installs hardened units: `dnscount-serve`, `dnscount-caddy-log` (tails Caddy's JSON access log, so every Caddy site is recorded) and a daily `dnscount-backup.timer` (keeps 7 copies in `/var/lib/dnscount/backups`)

For Caddy, add the marked blocks from `deploy/Caddyfile.example` to each site, then `systemctl reload caddy`.

To query on the host:

```sh
alias dnscount='sudo -u dnscount env DNSCOUNT_DB=/var/lib/dnscount/dnscount.db dnscount'
```

## Deploy (NixOS)

The flake exports `packages.<system>.dnscount` and `nixosModules.default` (`services.dnscount`). The module's units have the same hardening as the systemd ones, plus a syslog receiver whose firewall opening is limited to the `allow` sources. It also installs `dnscount-admin`, which runs reports against the service database.

```nix
inputs.dnscount.url = "github:<you>/dnscount";
# modules = [ dnscount.nixosModules.default { services.dnscount.enable = true; } ];
```

The full home setup is in [docs/homelab.md](docs/homelab.md): router syslog, Jellyfin behind Caddy, and Transmission/Jackett confined to a Mullvad namespace (`deploy/nixos/`). `nix build .#checks.x86_64-linux.module` boots a VM that tests the module.

## 1. Counter

```sh
dnscount serve -db dnscount.db -addr :8080 -token "$(openssl rand -hex 16)"
```

- `GET /counter.svg?site=blog`: counts one visit and returns the image. `&noinc=1` returns it without counting.
- `GET /counter.txt?site=blog`: the plain number.
- `GET /counter.js`: inserts the image where its `<script data-site=...>` tag sits.

Each IP gets 30 counts per minute (`-counter-limit`). Requests over the limit still get the image but aren't counted.

## 2. Request logging

**From Go code:** wrap your handler.

```go
sink := middleware.NewRemoteSink("http://collector:8080/ingest", token) // or middleware.NewLocalSink(store)
defer sink.Close()
http.ListenAndServe(":8000", middleware.Wrap(mux, sink, middleware.Options{
	Site:           "blog",
	TrustedProxies: proxies, // only these peers' X-Forwarded-For is believed
	SkipPaths:      []string{"/healthz"},
}))
```

A full example is in `examples/app`. Sinks never block the app: when the buffer is full, a hit is dropped. After 5 failed writes in a row, a sink stops trying for 30s.

**From access logs:**

```sh
dnscount ingest-access -format combined -site www /var/log/nginx/access.log
dnscount ingest-access -format caddy -follow /var/log/caddy/access.log
```

Values of credential-looking query parameters (`api_key`, `ApiKey`, `token`, `access_token`, `X-Emby-Token`, ...) are stored as `REDACTED`, in the query and in the referer, whichever path a hit comes in by.

Lines that aren't a normal `GET /path HTTP/1.1` request (TLS sent to an HTTP port, scanner junk) are kept, with the raw request as the path.

## 3. UniFi DNS + firewall

1. On the analysis host:
   `dnscount syslog -listen udp://:5514 -allow <router-ip> -raw ./raw`
2. In UniFi Network, open Settings → CyberSecure/System → Remote Logging (syslog/SIEM) and point it at that host on port 5514.
3. Turn on DNS query logging on the router, with either of these. Read the caveats at the top of the script first.
   - `ssh root@<router> 'sh -s' < scripts/unifi-dns-blocking.sh` also blocks ads with HaGeZi's lists and survives reboots. Turn off UniFi's Ad Blocking with it, because that hides the real client.
   - `ssh root@<router> 'sh -s' < scripts/unifi-enable-dns-log.sh` only logs, and is wiped on reboot.
4. Firewall lines only appear for rules that have logging turned on.

`-raw` keeps every received line in daily files. If a parser missed something, re-ingest with `dnscount ingest-dns -format unifi raw/*.log`. That's safe: rows dedup on a line hash, so re-imports add nothing.

Other ways to get logs off the router (SSH pull, offline bundles) are written up in `ingest/syslog/syslog.go`.

Also supported: `-format dnsmasq` (Pi-hole logs too) and `-format adguard` (`querylog.json`).

Timestamps in syslog-style lines carry no timezone. They're read in the analysis host's local zone, so keep it the same as the router's.

## Reports

```sh
dnscount report dns -domain example.com      # which clients looked it (and subdomains) up, how often, first/last,
                                             # and firewall-logged connections to the addresses it resolved to
dnscount report dns -client 192.168.1.5      # what that client looked up
dnscount report dns -top domain -since 24h
dnscount report hits -top ip -site blog -since 7d
dnscount report hits -ip 198.51.100.4
dnscount report trips -since 24h             # circuit-breaker trips
dnscount report trip 12                      # everything recorded about one trip
dnscount check                               # data sanity checks
sqlite3 dnscount.db                          # anything else
```

`GET /api` on the admin listener is a plain-text reference for every endpoint (parameters, response fields, status codes); the source is `server/api.txt`. The same data is available as JSON from the admin API (`127.0.0.1:8081` by default): `/api/hits`, `/api/top`, `/api/dns`, `/api/dns/top`, `/api/trips`, `/api/trips/{id}`, `/api/health`.

## Auth and circuit breakers

| Endpoint | Auth | Limits |
|---|---|---|
| counter | none | 30/min per IP |
| `POST /ingest` | `Authorization: Bearer <token>` (`-token` or `$DNSCOUNT_TOKEN`) | 1 MB body, 1000 hits/batch, 600 req/min, 10 bad/min per IP |
| admin API | none; it only listens on localhost (use an SSH tunnel) | none |
| syslog | source-IP allowlist (`-allow`, required) | 60k lines/min per source; trips if >50% of lines are malformed |

Status codes on `/ingest`:
- `400`: bad JSON or an invalid hit. The whole batch is rejected; nothing is partially inserted.
- `401`: missing or wrong token.
- `413`: body too large.
- `429` with `Retry-After`: only once that IP has tripped the breaker.

When a breaker trips, one row goes into `breaker_trips`. It holds everything we know about the client at that moment:
- all request headers (`Authorization`/`Cookie` are stored as a hash and length, never the value)
- the body sample and parse error
- the last 20 events, plus the first 20 rejected during cooldown
- the per-tenth-of-window rate curve and reverse DNS
- what the database already knows about that IP

A flood produces one row per trip, not one per request.
