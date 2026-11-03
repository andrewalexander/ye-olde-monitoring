// Package store is the SQLite layer: schema, inserts and the report queries.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"dnscount/hit"
	"dnscount/ingest"
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
	if err := migrate(db); err != nil {
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

const bumpCounter = `INSERT INTO counters(site, count) VALUES (?, 1)
	ON CONFLICT(site) DO UPDATE SET count = count + 1`

// InsertHits stores hits in one transaction, all or nothing. Hits with Count
// set bump their site's counter, but only if the hit wasn't a duplicate.
// It returns how many were new.
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
			if h.Count {
				if _, err := tx.Exec(bumpCounter, h.Site); err != nil {
					return 0, err
				}
			}
		}
	}
	return n, tx.Commit()
}

// Counter returns the public counter for site.
func (s *Store) Counter(site string) (int64, error) {
	var n int64
	err := s.queryRow(`SELECT count FROM counters WHERE site = ?`, site).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
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
			before := n
			if err := exec(insertHit, fmtTime(h.TS), h.Site, h.Source, h.ClientIP, h.ForwardedFor,
				h.Method, h.Host, h.Path, h.Query, h.Status, h.Bytes, h.UserAgent, h.Referer, h.Hash); err != nil {
				return 0, err
			}
			if h.Count && n > before {
				if _, err := tx.Exec(bumpCounter, h.Site); err != nil {
					return 0, err
				}
			}
		}
		if q := r.Query; q != nil {
			if err := exec(`INSERT OR IGNORE INTO dns_queries (ts, client_ip, client_name, domain, qtype, source, line_hash)
				VALUES (?,?,?,?,?,?,?)`, fmtTime(q.TS), q.ClientIP, q.ClientName, q.Domain, q.QType, q.Source, q.Hash); err != nil {
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

// Context is the context this Store's queries run under.
func (s *Store) Context() context.Context { return s.c() }
