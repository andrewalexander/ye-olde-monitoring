-- Timestamps are UTC text in a fixed-width format (see store.TimeFormat) so
-- they sort correctly and are readable straight from the sqlite3 shell.
-- line_hash is the dedup key: re-importing the same data is a no-op.

CREATE TABLE IF NOT EXISTS hits (
	id            INTEGER PRIMARY KEY,
	ts            TEXT    NOT NULL,
	site          TEXT    NOT NULL,
	source        TEXT    NOT NULL,
	client_ip     TEXT    NOT NULL,
	forwarded_for TEXT    NOT NULL DEFAULT '',
	method        TEXT    NOT NULL DEFAULT '',
	host          TEXT    NOT NULL DEFAULT '',
	path          TEXT    NOT NULL DEFAULT '',
	query         TEXT    NOT NULL DEFAULT '',
	status        INTEGER NOT NULL DEFAULT 0,
	bytes         INTEGER NOT NULL DEFAULT 0,
	user_agent    TEXT    NOT NULL DEFAULT '',
	referer       TEXT    NOT NULL DEFAULT '',
	line_hash     TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS hits_site ON hits(site);
CREATE INDEX IF NOT EXISTS hits_client_ip ON hits(client_ip);
CREATE INDEX IF NOT EXISTS hits_ts ON hits(ts);

CREATE TABLE IF NOT EXISTS counters (
	site  TEXT PRIMARY KEY,
	count INTEGER NOT NULL DEFAULT 0
);

-- Lookups: who asked for what.
CREATE TABLE IF NOT EXISTS dns_queries (
	id          INTEGER PRIMARY KEY,
	ts          TEXT NOT NULL,
	client_ip   TEXT NOT NULL,
	client_name TEXT NOT NULL DEFAULT '',
	domain      TEXT NOT NULL,
	qtype       TEXT NOT NULL DEFAULT '',
	source      TEXT NOT NULL,
	line_hash   TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS dns_queries_domain ON dns_queries(domain);
CREATE INDEX IF NOT EXISTS dns_queries_client_ip ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS dns_queries_ts ON dns_queries(ts);

-- Answers: what a name resolved to (reply/cached/forwarded/blocked/...).
CREATE TABLE IF NOT EXISTS dns_replies (
	id        INTEGER PRIMARY KEY,
	ts        TEXT NOT NULL,
	domain    TEXT NOT NULL,
	answer    TEXT NOT NULL DEFAULT '',
	status    TEXT NOT NULL,
	source    TEXT NOT NULL,
	line_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS dns_replies_domain ON dns_replies(domain);
CREATE INDEX IF NOT EXISTS dns_replies_answer ON dns_replies(answer);

-- Connections seen by the router firewall (only rules with logging on).
CREATE TABLE IF NOT EXISTS connections (
	id        INTEGER PRIMARY KEY,
	ts        TEXT    NOT NULL,
	client_ip TEXT    NOT NULL,
	dst_ip    TEXT    NOT NULL,
	dst_port  INTEGER NOT NULL DEFAULT 0,
	proto     TEXT    NOT NULL DEFAULT '',
	action    TEXT    NOT NULL DEFAULT '',
	rule      TEXT    NOT NULL DEFAULT '',
	source    TEXT    NOT NULL,
	line_hash TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS connections_client_ip ON connections(client_ip);
CREATE INDEX IF NOT EXISTS connections_dst_ip ON connections(dst_ip);

-- One row per circuit-breaker trip, with everything we knew about the
-- offender at that moment in detail_json.
CREATE TABLE IF NOT EXISTS breaker_trips (
	id                         INTEGER PRIMARY KEY,
	tripped_at                 TEXT    NOT NULL,
	cooldown_until             TEXT    NOT NULL,
	ended_at                   TEXT    NOT NULL DEFAULT '',
	breaker                    TEXT    NOT NULL,
	key                        TEXT    NOT NULL,
	reason                     TEXT    NOT NULL,
	window_events              INTEGER NOT NULL,
	window_bad                 INTEGER NOT NULL,
	suppressed_during_cooldown INTEGER NOT NULL DEFAULT 0,
	first_seen_in_window       TEXT    NOT NULL,
	detail_json                TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS breaker_trips_key ON breaker_trips(key);
CREATE INDEX IF NOT EXISTS breaker_trips_tripped_at ON breaker_trips(tripped_at);

-- One row per IDS/IPS alert from the router: which signature matched traffic
-- between which addresses, and whether the router let it through (allowed)
-- or dropped it (blocked).
CREATE TABLE IF NOT EXISTS ids_alerts (
	id           INTEGER PRIMARY KEY,
	ts           TEXT    NOT NULL,
	src_ip       TEXT    NOT NULL,
	src_port     INTEGER NOT NULL DEFAULT 0,
	dst_ip       TEXT    NOT NULL DEFAULT '',
	dst_port     INTEGER NOT NULL DEFAULT 0,
	proto        TEXT    NOT NULL DEFAULT '',
	action       TEXT    NOT NULL,
	signature    TEXT    NOT NULL DEFAULT '',
	signature_id INTEGER NOT NULL DEFAULT 0,
	category     TEXT    NOT NULL DEFAULT '',
	severity     INTEGER NOT NULL DEFAULT 0,
	source       TEXT    NOT NULL,
	-- From UniFi's CEF events: the router's direction, the LAN device at
	-- either end (CEF often has no address for it) and the policy that fired.
	-- Added after the table shipped: see store.migrate.
	direction    TEXT    NOT NULL DEFAULT '',
	src_name     TEXT    NOT NULL DEFAULT '',
	src_mac      TEXT    NOT NULL DEFAULT '',
	dst_name     TEXT    NOT NULL DEFAULT '',
	dst_mac      TEXT    NOT NULL DEFAULT '',
	policy       TEXT    NOT NULL DEFAULT '',
	line_hash    TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ids_alerts_ts ON ids_alerts(ts);
CREATE INDEX IF NOT EXISTS ids_alerts_src_ip ON ids_alerts(src_ip);

-- fail2ban's bans and unbans, one row per event, read from its log
-- (dnscount ingest-bans). Pairing a ban with its unban gives the
-- window in which that IP should have got nothing through.
CREATE TABLE IF NOT EXISTS bans (
	id        INTEGER PRIMARY KEY,
	ts        TEXT    NOT NULL,
	event     TEXT    NOT NULL, -- ban | unban
	jail      TEXT    NOT NULL,
	ip        TEXT    NOT NULL,
	ports     TEXT    NOT NULL DEFAULT '', -- the jail's port setting; '' is all
	bantime_s INTEGER NOT NULL DEFAULT 0,
	failures  INTEGER NOT NULL DEFAULT 0,
	line_hash TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip, jail, ts);
CREATE INDEX IF NOT EXISTS bans_ts ON bans(ts);

-- LAN devices seen at an address: DHCP leases, UniFi client events and the
-- router's neighbour table. A device's name at a time is its latest
-- sighting at or before then; IPv6 addresses get theirs through the MAC.
CREATE TABLE IF NOT EXISTS lan_sightings (
	id        INTEGER PRIMARY KEY,
	ts        TEXT NOT NULL,
	ip        TEXT NOT NULL DEFAULT '', -- '' when the event had only a MAC
	mac       TEXT NOT NULL,
	hostname  TEXT NOT NULL DEFAULT '',
	alias     TEXT NOT NULL DEFAULT '',
	network   TEXT NOT NULL DEFAULT '',
	iface     TEXT NOT NULL DEFAULT '',
	event     TEXT NOT NULL DEFAULT '',
	source    TEXT NOT NULL,
	line_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS lan_sightings_ip ON lan_sightings(ip, ts);
CREATE INDEX IF NOT EXISTS lan_sightings_mac ON lan_sightings(mac, ts);
CREATE INDEX IF NOT EXISTS lan_sightings_ts ON lan_sightings(ts);
