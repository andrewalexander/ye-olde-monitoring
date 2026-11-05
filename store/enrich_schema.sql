-- The explorer's own database (explore.db). Never part of dnscount.db: only
-- the explorer writes here, so nothing in it can hold up ingest.

-- Every public IP and domain seen in dnscount.db, kept up to date from each
-- table's new rows (see cursors). roles is a bitmask of where it was seen
-- (store.Role*). checked_at = '' means not yet matched against the lists.
CREATE TABLE IF NOT EXISTS indicators (
	indicator  TEXT    PRIMARY KEY,
	kind       TEXT    NOT NULL, -- ip | domain
	first_seen TEXT    NOT NULL,
	last_seen  TEXT    NOT NULL,
	roles      INTEGER NOT NULL DEFAULT 0,
	checked_at TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS indicators_last_seen ON indicators(last_seen);
CREATE INDEX IF NOT EXISTS indicators_checked ON indicators(checked_at);

-- Addresses that used the router's DNS: LAN devices, even ones with global
-- IPv6 addresses. They're never treated as public.
CREATE TABLE IF NOT EXISTS lan_clients (
	ip         TEXT PRIMARY KEY,
	first_seen TEXT NOT NULL,
	last_seen  TEXT NOT NULL
);

-- How far into each dnscount.db table the index has read (by row id; those
-- tables are append-only).
CREATE TABLE IF NOT EXISTS cursors (
	tbl     TEXT    PRIMARY KEY,
	last_id INTEGER NOT NULL
);

-- Everything known about an indicator, one row per provider: "provider X
-- says Y about it, as of Z". Every column means the same for every provider;
-- what the provider said is in facts, as JSON labelled by provider.
--   method     downloaded (a list or table we fetch whole and match locally)
--              | queried (a service we ask per indicator; the row is its cache)
--   verdict    the provider's own judgement, if it gives one
--   current    1 = the provider says something about it now (on the list;
--              the last answer found it)
--   first_seen, last_seen   when it first / last said so
--   ended_at   when it stopped (left the list; a refresh found nothing)
--   version    which state of the provider's data this reflects (the list
--              file's hash; the fetch time)
--   raw        the full answer, for queried providers
-- Downloaded rows can be rebuilt for free; queried rows cost quota to get
-- again, so only downloaded rows are ever dropped (see store.OpenEnrich).
CREATE TABLE IF NOT EXISTS enrichment (
	provider   TEXT    NOT NULL,
	indicator  TEXT    NOT NULL,
	kind       TEXT    NOT NULL, -- ip | domain
	method     TEXT    NOT NULL, -- downloaded | queried
	verdict    TEXT    NOT NULL DEFAULT '',
	current    INTEGER NOT NULL,
	first_seen TEXT    NOT NULL,
	last_seen  TEXT    NOT NULL,
	ended_at   TEXT    NOT NULL DEFAULT '',
	version    TEXT    NOT NULL,
	facts      TEXT    NOT NULL DEFAULT '{}',
	raw        TEXT    NOT NULL DEFAULT '',
	PRIMARY KEY (provider, indicator)
);
CREATE INDEX IF NOT EXISTS enrichment_indicator ON enrichment(indicator);
CREATE INDEX IF NOT EXISTS enrichment_current ON enrichment(current, method, verdict);

-- Every request sent to a queried provider: what left the box, when, and
-- what it cost. Budgets are counted from here. Not enrichment data.
CREATE TABLE IF NOT EXISTS lookup_requests (
	id        INTEGER PRIMARY KEY,
	provider  TEXT    NOT NULL,
	indicator TEXT    NOT NULL, -- or several, comma-separated, for a batch
	ts        TEXT    NOT NULL,
	status    TEXT    NOT NULL, -- ok | not_found | error | HTTP status
	units     INTEGER NOT NULL DEFAULT 1, -- credits or quota used
	error     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS lookup_requests_ts ON lookup_requests(provider, ts);

-- The version of each list last reconciled.
CREATE TABLE IF NOT EXISTS feed_versions (
	provider  TEXT    PRIMARY KEY,
	version   TEXT    NOT NULL,
	loaded_at TEXT    NOT NULL,
	entries   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_asn (
	ip           TEXT    PRIMARY KEY,
	asn          INTEGER NOT NULL,
	as_owner     TEXT    NOT NULL DEFAULT '',
	country      TEXT    NOT NULL DEFAULT '',
	list_version TEXT    NOT NULL,
	updated_at   TEXT    NOT NULL
);

-- An address whose AS or owner changed between iptoasn versions.
CREATE TABLE IF NOT EXISTS ip_asn_changes (
	ip        TEXT    NOT NULL,
	ts        TEXT    NOT NULL,
	old_asn   INTEGER NOT NULL,
	new_asn   INTEGER NOT NULL,
	old_owner TEXT    NOT NULL,
	new_owner TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS ip_asn_changes_ip ON ip_asn_changes(ip, ts);

-- Bookkeeping: index_version (see store.indexVersion).
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
