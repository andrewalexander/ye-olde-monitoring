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

-- One row per indicator per list: its current state on that list.
CREATE TABLE IF NOT EXISTS enrichment (
	provider     TEXT    NOT NULL, -- feed:<name>
	indicator    TEXT    NOT NULL,
	kind         TEXT    NOT NULL,
	verdict      TEXT    NOT NULL, -- malicious | suspicious | info
	detail       TEXT    NOT NULL DEFAULT '',
	matched_via  TEXT    NOT NULL DEFAULT '', -- the listed IP, CIDR or parent domain
	listed       INTEGER NOT NULL,            -- 1 = on the list now
	first_listed TEXT    NOT NULL,
	last_listed  TEXT    NOT NULL,
	removed_at   TEXT    NOT NULL DEFAULT '',
	list_version TEXT    NOT NULL,
	PRIMARY KEY (provider, indicator)
);
CREATE INDEX IF NOT EXISTS enrichment_indicator ON enrichment(indicator);
CREATE INDEX IF NOT EXISTS enrichment_listed ON enrichment(listed, verdict);

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
