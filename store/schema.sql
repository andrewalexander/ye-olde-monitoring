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
