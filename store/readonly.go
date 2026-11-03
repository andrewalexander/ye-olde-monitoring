package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"fmt"
	"strings"

	"modernc.org/sqlite"
)

//go:embed enrich_schema.sql
var enrichSchema string

// OpenEnrich opens (creating if needed) the explorer's own database: the
// indicator index and everything learned about each indicator. It's written
// only by the explorer, so it can never hold up ingest.
func OpenEnrich(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(enrichSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("enrich schema: %w", err)
	}
	return &Store{db: db}, nil
}

// OpenReadOnly opens the live database for reading only, with enrichPath
// (made by OpenEnrich) attached read-only as "enrich". Every write through
// this handle fails, to either file. In WAL mode its reads never block the
// writers; keep each query short (WithContext) so checkpoints aren't held
// back for long.
func OpenReadOnly(path, enrichPath string, maxConns int) (*Store, error) {
	if strings.ContainsAny(path+enrichPath, "?#'") {
		return nil, fmt.Errorf("database paths can't contain ?, # or '")
	}
	c := &roConnector{
		dsn:    "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)",
		attach: "file:" + enrichPath + "?mode=ro",
	}
	db := sql.OpenDB(c)
	if maxConns <= 0 {
		maxConns = 4
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// roConnector attaches the enrich database to every new connection.
type roConnector struct{ dsn, attach string }

func (c *roConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	ex, ok := conn.(driver.ExecerContext)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("sqlite connection can't exec")
	}
	if _, err := ex.ExecContext(ctx, `ATTACH DATABASE '`+c.attach+`' AS enrich`, nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("attach %s: %w", c.attach, err)
	}
	return conn, nil
}

func (c *roConnector) Driver() driver.Driver { return &sqlite.Driver{} }
