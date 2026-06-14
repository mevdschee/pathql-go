package db

// This file persists the runtime-tunable connection-pool parameters so admin
// changes survive a restart. The global defaults live in one row of
// <authPrefix>pool_settings (id = 1); per-user overrides live in nullable
// columns on <authPrefix>users. Durations are stored as whole milliseconds in
// the *_ms bigint columns and exposed as time.Duration through PoolParams.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jmoiron/sqlx"
)

// poolPrefixRe validates the auth table prefix before it is interpolated into a
// table name. It is the same identifier-safe rule used elsewhere in the
// codebase: a SQL identifier start followed by an identifier body.
var poolPrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// PoolStore persists pool parameters in the auth schema: the global defaults in
// <authPrefix>pool_settings and the per-user overrides in nullable columns on
// <authPrefix>users. Only the validated prefix is interpolated into the table
// names; every value is bound with PostgreSQL $N placeholders.
type PoolStore struct {
	db *sqlx.DB

	settingsTable string
	usersTable    string
}

// NewPoolStore builds a PoolStore over the <authTablePrefix>pool_settings and
// <authTablePrefix>users tables. authTablePrefix must match
// ^[A-Za-z_][A-Za-z0-9_]*$ because it is interpolated into the table names;
// everything else is bound.
func NewPoolStore(db *sqlx.DB, authTablePrefix string) (*PoolStore, error) {
	if !poolPrefixRe.MatchString(authTablePrefix) {
		return nil, fmt.Errorf("db: invalid auth table prefix %q: must match %s", authTablePrefix, poolPrefixRe.String())
	}
	return &PoolStore{
		db:            db,
		settingsTable: authTablePrefix + "pool_settings",
		usersTable:    authTablePrefix + "users",
	}, nil
}

// globalRow mirrors the pool_settings columns for sqlx scanning. The durations
// are stored as whole milliseconds.
type globalRow struct {
	MaxOpen           int   `db:"max_open"`
	MaxIdle           int   `db:"max_idle"`
	ConnMaxLifetimeMs int64 `db:"conn_max_lifetime_ms"`
	ConnMaxIdleTimeMs int64 `db:"conn_max_idle_time_ms"`
}

// LoadGlobal reads the single id = 1 row of the pool_settings table. ok is
// false (with a nil error) when the row does not exist yet, so the caller can
// fall back to the config defaults and seed the row. The *_ms columns are
// converted from milliseconds to time.Duration.
func (s *PoolStore) LoadGlobal(ctx context.Context) (pp PoolParams, ok bool, err error) {
	query := fmt.Sprintf(`
SELECT max_open, max_idle, conn_max_lifetime_ms, conn_max_idle_time_ms
FROM %s
WHERE id = 1`, s.settingsTable)

	var row globalRow
	if err := s.db.GetContext(ctx, &row, query); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PoolParams{}, false, nil
		}
		return PoolParams{}, false, err
	}
	return PoolParams{
		MaxOpen:         row.MaxOpen,
		MaxIdle:         row.MaxIdle,
		ConnMaxLifetime: time.Duration(row.ConnMaxLifetimeMs) * time.Millisecond,
		ConnMaxIdleTime: time.Duration(row.ConnMaxIdleTimeMs) * time.Millisecond,
	}, true, nil
}

// SaveGlobal upserts the single id = 1 row of the pool_settings table. The
// durations are stored as whole milliseconds.
func (s *PoolStore) SaveGlobal(ctx context.Context, pp PoolParams) error {
	query := fmt.Sprintf(`
INSERT INTO %s (id, max_open, max_idle, conn_max_lifetime_ms, conn_max_idle_time_ms)
VALUES (1, $1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET
  max_open = EXCLUDED.max_open,
  max_idle = EXCLUDED.max_idle,
  conn_max_lifetime_ms = EXCLUDED.conn_max_lifetime_ms,
  conn_max_idle_time_ms = EXCLUDED.conn_max_idle_time_ms`, s.settingsTable)

	_, err := s.db.ExecContext(ctx, query,
		pp.MaxOpen,
		pp.MaxIdle,
		pp.ConnMaxLifetime.Milliseconds(),
		pp.ConnMaxIdleTime.Milliseconds(),
	)
	return err
}

// overrideRow mirrors the per-user override columns for sqlx scanning. Every
// override column is nullable; an override is present iff pool_max_open is
// non-null, and the four columns are always written together.
type overrideRow struct {
	ID                int64         `db:"id"`
	MaxOpen           sql.NullInt64 `db:"pool_max_open"`
	MaxIdle           sql.NullInt64 `db:"pool_max_idle"`
	ConnMaxLifetimeMs sql.NullInt64 `db:"pool_conn_max_lifetime_ms"`
	ConnMaxIdleTimeMs sql.NullInt64 `db:"pool_conn_max_idle_time_ms"`
}

// LoadOverrides reads every per-user pool override from the users table. An
// override is present iff pool_max_open is non-null; the four override columns
// are written together, so all four are read. It returns a map of user id to
// the override parameters, with the *_ms columns converted from milliseconds to
// time.Duration.
func (s *PoolStore) LoadOverrides(ctx context.Context) (map[int64]PoolParams, error) {
	query := fmt.Sprintf(`
SELECT id, pool_max_open, pool_max_idle, pool_conn_max_lifetime_ms, pool_conn_max_idle_time_ms
FROM %s
WHERE pool_max_open IS NOT NULL`, s.usersTable)

	var rows []overrideRow
	if err := s.db.SelectContext(ctx, &rows, query); err != nil {
		return nil, err
	}
	out := make(map[int64]PoolParams, len(rows))
	for _, row := range rows {
		out[row.ID] = PoolParams{
			MaxOpen:         int(row.MaxOpen.Int64),
			MaxIdle:         int(row.MaxIdle.Int64),
			ConnMaxLifetime: time.Duration(row.ConnMaxLifetimeMs.Int64) * time.Millisecond,
			ConnMaxIdleTime: time.Duration(row.ConnMaxIdleTimeMs.Int64) * time.Millisecond,
		}
	}
	return out, nil
}

// SaveOverride writes or clears the per-user pool override on the users row with
// the given id. A nil pp clears the override by setting all four columns to
// NULL so the user inherits the global defaults. A non-nil pp sets all four
// columns together, storing the durations as whole milliseconds.
func (s *PoolStore) SaveOverride(ctx context.Context, userID int64, pp *PoolParams) error {
	if pp == nil {
		query := fmt.Sprintf(`
UPDATE %s SET
  pool_max_open = NULL,
  pool_max_idle = NULL,
  pool_conn_max_lifetime_ms = NULL,
  pool_conn_max_idle_time_ms = NULL
WHERE id = $1`, s.usersTable)
		_, err := s.db.ExecContext(ctx, query, userID)
		return err
	}

	query := fmt.Sprintf(`
UPDATE %s SET
  pool_max_open = $1,
  pool_max_idle = $2,
  pool_conn_max_lifetime_ms = $3,
  pool_conn_max_idle_time_ms = $4
WHERE id = $5`, s.usersTable)
	_, err := s.db.ExecContext(ctx, query,
		pp.MaxOpen,
		pp.MaxIdle,
		pp.ConnMaxLifetime.Milliseconds(),
		pp.ConnMaxIdleTime.Milliseconds(),
		userID,
	)
	return err
}
