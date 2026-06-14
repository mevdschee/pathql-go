package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jmoiron/sqlx"
)

// ErrNotFound is returned by a UserStore when no matching row exists.
var ErrNotFound = errors.New("auth: not found")

// APIKeyRecord is the result of an API-key lookup, joined to its owning user.
type APIKeyRecord struct {
	UserID    int64
	AppUser   string     // from the joined user row
	KeyHash   []byte     // sha-256 of the full key
	Enabled   bool       // key.enabled AND user.enabled
	ExpiresAt *time.Time // nil = never expires
}

// UserRecord is the result of a username lookup.
type UserRecord struct {
	UserID       int64
	Username     string
	PasswordHash string // bcrypt; empty disables Basic for this user
	AppUser      string
	Enabled      bool
}

// UserStore is the persistence interface the authenticators depend on.
type UserStore interface {
	// LookupAPIKeyByPrefix returns the key (joined to its user) matching the
	// given non-secret prefix, or ErrNotFound if none.
	LookupAPIKeyByPrefix(ctx context.Context, prefix string) (*APIKeyRecord, error)
	// LookupUserByUsername returns the user matching username, or ErrNotFound.
	LookupUserByUsername(ctx context.Context, username string) (*UserRecord, error)
	// TouchAPIKey updates last_used_at for the key. Best effort; callers ignore
	// the error.
	TouchAPIKey(ctx context.Context, userID int64, prefix string) error
}

// tablePrefixRe validates the auth table prefix. It is interpolated directly
// into SQL table names, so it must be a strict identifier-safe token.
var tablePrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// sqlUserStore is a PostgreSQL-backed UserStore over the pathql_auth_ tables.
type sqlUserStore struct {
	db *sqlx.DB

	lookupKeyQuery  string
	lookupUserQuery string
	touchKeyQuery   string
}

// NewSQLUserStore builds a UserStore over the <tablePrefix>users and
// <tablePrefix>api_keys tables. tablePrefix must match
// ^[A-Za-z_][A-Za-z0-9_]*$ (it is interpolated into table names; everything
// else is bound). The queries use PostgreSQL ($N) placeholders, the primary
// target.
func NewSQLUserStore(db *sqlx.DB, tablePrefix string) (UserStore, error) {
	if !tablePrefixRe.MatchString(tablePrefix) {
		return nil, fmt.Errorf("auth: invalid table prefix %q: must match %s", tablePrefix, tablePrefixRe.String())
	}

	usersTable := tablePrefix + "users"
	keysTable := tablePrefix + "api_keys"

	s := &sqlUserStore{
		db: db,
		// Join api_keys to users so we get app_user and the combined enabled
		// flag (key.enabled AND user.enabled) in one query. All values are
		// bound; only the validated prefix is interpolated.
		lookupKeyQuery: fmt.Sprintf(`
SELECT
  k.user_id                       AS user_id,
  u.app_user                      AS app_user,
  k.key_hash                      AS key_hash,
  (k.enabled AND u.enabled)       AS enabled,
  k.expires_at                    AS expires_at
FROM %s k
JOIN %s u ON u.id = k.user_id
WHERE k.key_prefix = $1`, keysTable, usersTable),

		lookupUserQuery: fmt.Sprintf(`
SELECT
  id            AS user_id,
  username      AS username,
  COALESCE(password_hash, '') AS password_hash,
  app_user      AS app_user,
  enabled       AS enabled
FROM %s
WHERE username = $1`, usersTable),

		touchKeyQuery: fmt.Sprintf(`
UPDATE %s
SET last_used_at = now()
WHERE key_prefix = $1 AND user_id = $2`, keysTable),
	}
	return s, nil
}

// apiKeyRow mirrors the lookupKeyQuery result for sqlx scanning.
type apiKeyRow struct {
	UserID    int64        `db:"user_id"`
	AppUser   string       `db:"app_user"`
	KeyHash   []byte       `db:"key_hash"`
	Enabled   bool         `db:"enabled"`
	ExpiresAt sql.NullTime `db:"expires_at"`
}

func (s *sqlUserStore) LookupAPIKeyByPrefix(ctx context.Context, prefix string) (*APIKeyRecord, error) {
	var row apiKeyRow
	err := s.db.GetContext(ctx, &row, s.lookupKeyQuery, prefix)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rec := &APIKeyRecord{
		UserID:  row.UserID,
		AppUser: row.AppUser,
		KeyHash: row.KeyHash,
		Enabled: row.Enabled,
	}
	if row.ExpiresAt.Valid {
		t := row.ExpiresAt.Time
		rec.ExpiresAt = &t
	}
	return rec, nil
}

// userRow mirrors the lookupUserQuery result for sqlx scanning.
type userRow struct {
	UserID       int64  `db:"user_id"`
	Username     string `db:"username"`
	PasswordHash string `db:"password_hash"`
	AppUser      string `db:"app_user"`
	Enabled      bool   `db:"enabled"`
}

func (s *sqlUserStore) LookupUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	var row userRow
	err := s.db.GetContext(ctx, &row, s.lookupUserQuery, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &UserRecord{
		UserID:       row.UserID,
		Username:     row.Username,
		PasswordHash: row.PasswordHash,
		AppUser:      row.AppUser,
		Enabled:      row.Enabled,
	}, nil
}

func (s *sqlUserStore) TouchAPIKey(ctx context.Context, userID int64, prefix string) error {
	_, err := s.db.ExecContext(ctx, s.touchKeyQuery, prefix, userID)
	return err
}
