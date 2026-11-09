// Package store is the SQLite layer: schema, inserts and the report queries.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

//go:embed schema.sql
var schema string

// TimeFormat is fixed width so text timestamps sort chronologically.
const TimeFormat = "2006-01-02T15:04:05.000000000Z"

func fmtTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(TimeFormat, s)
	return t
}

type Store struct {
	db  *sql.DB
	ctx context.Context // nil means context.Background()
}

// WithContext returns a Store whose queries run under ctx, so a request
// deadline cancels a slow query instead of letting it hold a read open.
func (s *Store) WithContext(ctx context.Context) *Store {
	c := *s
	c.ctx = ctx
	return &c
}

func (s *Store) c() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(s.c(), q, args...)
}
func (s *Store) queryRow(q string, args ...any) *sql.Row {
	return s.db.QueryRowContext(s.c(), q, args...)
}

// column runs q and returns its one (string) column.
func (s *Store) column(q string, args ...any) ([]string, error) {
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// columnSet is column as a set.
func (s *Store) columnSet(q string, args ...any) (map[string]bool, error) {
	vs, err := s.column(q, args...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(vs))
	for _, v := range vs {
		out[v] = true
	}
	return out, nil
}

func (s *Store) exec(q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(s.c(), q, args...)
}

// Open opens (creating if needed) the database at path. ":memory:" works for
// tests.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer at a time is all SQLite does anyway; this avoids SQLITE_BUSY
	// and keeps an in-memory database a single database.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS counters`); err != nil { // the old write-side counter
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := dropColumns(db, droppedColumns); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for ad-hoc queries in tests and tools.
func (s *Store) DB() *sql.DB { return s.db }

const insertHit = `INSERT OR IGNORE INTO hits
	(ts, site, source, client_ip, forwarded_for, method, host, path, query, status, bytes, user_agent, referer, line_hash)
	VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// InsertHits stores hits in one transaction, all or nothing, and returns how
// many were new.
func (s *Store) InsertHits(hits []hit.Hit) (int, error) {
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, h := range hits {
		res, err := tx.Exec(insertHit, fmtTime(h.TS), h.Site, h.Source, h.ClientIP, h.ForwardedFor,
			h.Method, h.Host, h.Path, h.Query, h.Status, h.Bytes, h.UserAgent, h.Referer, h.Hash)
		if err != nil {
			return 0, err
		}
		if c, _ := res.RowsAffected(); c == 1 {
			n++
		}
	}
	return n, tx.Commit()
}

// visitorsQuery is the visitor counter: one per client IP per UTC day that
// loaded a page of site. A page is a successful (2xx, or 304 from a cached
// reload) GET of "/", a path ending in "/" or ".html", or a path with no dot
// after its last slash. Assets, errors, probes and the counter image itself
// don't count, and it doesn't matter which source (Caddy's log, middleware,
// an imported log) recorded the hit or whether two of them did.
const visitorsQuery = `SELECT count(*) FROM (
	SELECT DISTINCT client_ip, substr(ts, 1, 10) FROM hits
	WHERE site = ? AND method = 'GET' AND (status BETWEEN 200 AND 299 OR status = 304)
	  AND (path GLOB '*/' OR path GLOB '*.html' OR path NOT GLOB '*/*.*'))`

// Visitors returns the visitor counter for site (see visitorsQuery). It's
// computed from hits, so it can always be recomputed and is never written.
func (s *Store) Visitors(site string) (int64, error) {
	var n int64
	err := s.queryRow(visitorsQuery, site).Scan(&n)
	return n, err
}

// InsertRecords stores parsed log records in one transaction and returns how
// many rows were new across all tables.
func (s *Store) InsertRecords(recs []ingest.Record) (int, error) {
	tx, err := s.db.BeginTx(s.c(), nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	exec := func(q string, args ...any) error {
		res, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		c, _ := res.RowsAffected()
		n += int(c)
		return nil
	}
	for _, r := range recs {
		if h := r.Hit; h != nil {
			h.Sanitize()
			if err := exec(insertHit, fmtTime(h.TS), h.Site, h.Source, h.ClientIP, h.ForwardedFor,
				h.Method, h.Host, h.Path, h.Query, h.Status, h.Bytes, h.UserAgent, h.Referer, h.Hash); err != nil {
				return 0, err
			}
		}
		if q := r.Query; q != nil {
			if err := exec(`INSERT OR IGNORE INTO dns_queries (ts, client_ip, domain, qtype, source, line_hash)
				VALUES (?,?,?,?,?,?)`, fmtTime(q.TS), q.ClientIP, q.Domain, q.QType, q.Source, q.Hash); err != nil {
				return 0, err
			}
		}
		if p := r.Reply; p != nil {
			if err := exec(`INSERT OR IGNORE INTO dns_replies (ts, domain, answer, status, source, line_hash)
				VALUES (?,?,?,?,?,?)`, fmtTime(p.TS), p.Domain, p.Answer, p.Status, p.Source, p.Hash); err != nil {
				return 0, err
			}
		}
		if c := r.Conn; c != nil {
			if err := exec(`INSERT OR IGNORE INTO connections (ts, client_ip, dst_ip, dst_port, proto, action, rule, source, line_hash)
				VALUES (?,?,?,?,?,?,?,?,?)`, fmtTime(c.TS), c.ClientIP, c.DstIP, c.DstPort, c.Proto, c.Action, c.Rule, c.Source, c.Hash); err != nil {
				return 0, err
			}
		}
		if a := r.Alert; a != nil {
			if err := exec(insertAlert,
				fmtTime(a.TS), a.SrcIP, a.SrcPort, a.DstIP, a.DstPort, a.Proto, a.Action,
				a.Signature, a.SignatureID, a.Category, a.Severity, a.Source,
				a.Direction, a.SrcName, a.SrcMAC, a.DstName, a.DstMAC, a.Policy, a.Hash); err != nil {
				return 0, err
			}
		}
		if v := r.Seen; v != nil {
			if err := exec(`INSERT OR IGNORE INTO lan_sightings (ts, ip, mac, hostname, alias, network, iface, event, source, line_hash)
				VALUES (?,?,?,?,?,?,?,?,?,?)`, fmtTime(v.TS), v.IP, v.MAC, v.Hostname, v.Alias, v.Network, v.Iface,
				v.Event, v.Source, v.Hash); err != nil {
				return 0, err
			}
		}
		if a := r.Auth; a != nil {
			if err := exec(`INSERT OR IGNORE INTO auth_failures (ts, source, ip, user, line_hash) VALUES (?,?,?,?,?)`,
				fmtTime(a.TS), a.Source, a.IP, a.User, a.Hash); err != nil {
				return 0, err
			}
		}
		if b := r.Ban; b != nil {
			q, args := insertBan, banArgs(b)
			if b.Event == "increase" {
				q, args = increaseBan, []any{int64(b.BanTime / time.Second), b.Jail, b.IP, fmtTime(b.TS), fmtTime(b.TS.Add(-time.Minute))}
			}
			if err := exec(q, args...); err != nil {
				return 0, err
			}
		}
	}
	return n, tx.Commit()
}

// Backup writes a consistent copy of the database to path (which must not
// exist) without stopping writers.
func (s *Store) Backup(path string) error {
	_, err := s.exec(`VACUUM INTO ?`, path)
	return err
}

// FormatTime is how timestamps are stored.
func FormatTime(t time.Time) string { return fmtTime(t) }
