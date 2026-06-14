// Package db provides a single shared, capped connection pool over
// pathsqlx.DB. It replaces the previous per-request pathsqlx.Connect so that
// the server holds one bounded pool for the lifetime of the process.
package db

import (
	"context"
	"time"

	"github.com/mevdschee/pathsqlx"
)

// OpenPool opens a shared connection pool (no per-request Connect) and applies
// caps. It uses pathsqlx.Open (lazy, no ping) so the process can start before
// the DB is reachable; callers may Ping separately. Returns an error for an
// unknown driver.
func OpenPool(driver, dsn string, maxOpen, maxIdle int, connMaxLifetime time.Duration) (*pathsqlx.DB, error) {
	db, err := pathsqlx.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	// pathsqlx.DB embeds *sqlx.DB which embeds *sql.DB, so the underlying
	// pool is reached via db.DB.DB.
	db.DB.DB.SetMaxOpenConns(maxOpen)
	db.DB.DB.SetMaxIdleConns(maxIdle)
	db.DB.DB.SetConnMaxLifetime(connMaxLifetime)
	return db, nil
}

// Ping verifies connectivity with a context.
func Ping(ctx context.Context, db *pathsqlx.DB) error {
	return db.DB.DB.PingContext(ctx)
}

// Close closes the pool.
func Close(db *pathsqlx.DB) error {
	return db.DB.DB.Close()
}
