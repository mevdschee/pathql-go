package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// UserAdmin performs admin-side writes to the <tablePrefix>users and
// <tablePrefix>api_keys tables that the UserStore reads. It is used by the
// server's admin routes to create and delete users and API keys. Role DDL is
// handled elsewhere; this only writes the auth rows.
type UserAdmin struct {
	db *sqlx.DB

	usersTable string
	keysTable  string
}

// NewUserAdmin builds a UserAdmin over the <tablePrefix>users and
// <tablePrefix>api_keys tables. tablePrefix must match the same rule as
// NewSQLUserStore (^[A-Za-z_][A-Za-z0-9_]*$); it is interpolated into table
// names, while everything else is bound. The queries use PostgreSQL ($N)
// placeholders.
func NewUserAdmin(db *sqlx.DB, tablePrefix string) (*UserAdmin, error) {
	if !tablePrefixRe.MatchString(tablePrefix) {
		return nil, fmt.Errorf("auth: invalid table prefix %q: must match %s", tablePrefix, tablePrefixRe.String())
	}
	return &UserAdmin{
		db:         db,
		usersTable: tablePrefix + "users",
		keysTable:  tablePrefix + "api_keys",
	}, nil
}

// AddUser inserts a new user and returns its id. If passwordHash is "", the
// password_hash column is stored as NULL, which disables HTTP Basic for that
// user. If appUser is "", it defaults to username. A duplicate username (unique
// violation) surfaces as a wrapped error.
func (a *UserAdmin) AddUser(ctx context.Context, username, appUser, passwordHash string) (int64, error) {
	if appUser == "" {
		appUser = username
	}

	// Store NULL for an empty password hash so HTTP Basic is disabled.
	var hash sql.NullString
	if passwordHash != "" {
		hash = sql.NullString{String: passwordHash, Valid: true}
	}

	query := fmt.Sprintf(`
INSERT INTO %s (username, password_hash, app_user, enabled)
VALUES ($1, $2, $3, true)
RETURNING id`, a.usersTable)

	var id int64
	if err := a.db.GetContext(ctx, &id, query, username, hash, appUser); err != nil {
		return 0, fmt.Errorf("auth: add user %q: %w", username, err)
	}
	return id, nil
}

// DeleteUser removes a user and all of its API keys in a single transaction. It
// returns true if a user row was deleted, false if no user with that id exists.
// The transaction is rolled back on any error.
func (a *UserAdmin) DeleteUser(ctx context.Context, id int64) (bool, error) {
	tx, err := a.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("auth: delete user %d: begin: %w", id, err)
	}

	deleteKeys := fmt.Sprintf(`DELETE FROM %s WHERE user_id = $1`, a.keysTable)
	if _, err := tx.ExecContext(ctx, deleteKeys, id); err != nil {
		_ = tx.Rollback()
		return false, fmt.Errorf("auth: delete user %d: delete api keys: %w", id, err)
	}

	deleteUser := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, a.usersTable)
	res, err := tx.ExecContext(ctx, deleteUser, id)
	if err != nil {
		_ = tx.Rollback()
		return false, fmt.Errorf("auth: delete user %d: delete user: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return false, fmt.Errorf("auth: delete user %d: rows affected: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("auth: delete user %d: commit: %w", id, err)
	}
	return affected > 0, nil
}

// AddAPIKey inserts an enabled API key for the given user. keyPrefix is the
// non-secret lookup prefix, keyHash is the sha-256 of the full key, and name is
// a human-readable label. All values are bound.
func (a *UserAdmin) AddAPIKey(ctx context.Context, userID int64, keyPrefix string, keyHash []byte, name string) error {
	query := fmt.Sprintf(`
INSERT INTO %s (user_id, key_prefix, key_hash, name, enabled)
VALUES ($1, $2, $3, $4, true)`, a.keysTable)

	if _, err := a.db.ExecContext(ctx, query, userID, keyPrefix, keyHash, name); err != nil {
		return fmt.Errorf("auth: add api key for user %d: %w", userID, err)
	}
	return nil
}
