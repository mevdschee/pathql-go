package db

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/mevdschee/pathsqlx"
)

// QueryOptions configures how RunQuery executes a query under Postgres
// row-level security: which session variable to bind the application user to,
// whether to use a read-only transaction, and an optional statement timeout.
type QueryOptions struct {
	// AppUser is the value bound to SessionVariable for this transaction.
	// When empty, no session variable is set.
	AppUser string
	// SessionVariable is the custom Postgres GUC name (e.g. "app.user"). It
	// must be schema-qualified (contain a dot). When empty, no session
	// variable is set.
	SessionVariable string
	// ReadOnly opens the transaction READ ONLY when true.
	ReadOnly bool
	// StatementTimeout, when > 0, sets a transaction-local statement_timeout.
	StatementTimeout time.Duration
	// IdleInTxTimeout, when > 0, sets a transaction-local
	// idle_in_transaction_session_timeout so a stalled transaction cannot pin a
	// connection indefinitely.
	IdleInTxTimeout time.Duration
	// WorkMemKB, when > 0, sets a transaction-local work_mem (in kB) so a single
	// sort/hash node cannot consume unbounded memory.
	WorkMemKB int
}

// sessionVariablePattern matches a valid custom Postgres GUC name. The name
// must start with a letter or underscore and may contain letters, digits,
// underscores and dots. A separate check requires at least one dot so the
// variable is schema-qualified (a hard requirement for custom GUCs).
var sessionVariablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// validateSessionVariable returns an error unless name is a syntactically
// valid, schema-qualified custom Postgres GUC name. It is the single source of
// truth for what RunQuery is willing to set, and is unit-tested directly.
func validateSessionVariable(name string) error {
	if !sessionVariablePattern.MatchString(name) {
		return fmt.Errorf("invalid session variable name %q", name)
	}
	if !regexpHasDot(name) {
		return fmt.Errorf("session variable %q must be schema-qualified (contain a dot)", name)
	}
	return nil
}

// regexpHasDot reports whether s contains a '.'. Kept tiny and explicit so the
// schema-qualification requirement is obvious at the call site.
func regexpHasDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

// applySessionSettings applies the transaction-local session settings from
// opts to tx using the function form of SET LOCAL (set_config(..., true)),
// which, unlike a bare SET, accepts bound parameters. This keeps the
// application user and the session-variable name as bound arguments instead of
// concatenating them into SQL.
//
// Order: statement_timeout first (if any), then the session variable (if any).
// It is factored out of RunQuery so it can be unit-tested against a recording
// fake driver without a real schema.
func applySessionSettings(ctx context.Context, tx *sqlx.Tx, opts QueryOptions) error {
	if opts.StatementTimeout > 0 {
		ms := strconv.FormatInt(int64(opts.StatementTimeout/time.Millisecond), 10)
		if _, err := tx.ExecContext(ctx, "SELECT set_config($1, $2, true)", "statement_timeout", ms); err != nil {
			return err
		}
	}
	if opts.IdleInTxTimeout > 0 {
		ms := strconv.FormatInt(int64(opts.IdleInTxTimeout/time.Millisecond), 10)
		if _, err := tx.ExecContext(ctx, "SELECT set_config($1, $2, true)", "idle_in_transaction_session_timeout", ms); err != nil {
			return err
		}
	}
	if opts.WorkMemKB > 0 {
		// work_mem with no unit is interpreted as kB by PostgreSQL. It is USERSET,
		// so a least-privilege (non-superuser) role may set it per transaction.
		if _, err := tx.ExecContext(ctx, "SELECT set_config($1, $2, true)", "work_mem", strconv.Itoa(opts.WorkMemKB)); err != nil {
			return err
		}
	}
	if opts.AppUser != "" && opts.SessionVariable != "" {
		if err := validateSessionVariable(opts.SessionVariable); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "SELECT set_config($1, $2, true)", opts.SessionVariable, opts.AppUser); err != nil {
			return err
		}
	}
	return nil
}

// RunQuery runs query inside a transaction so the SET LOCAL session settings
// apply on the same connection, then commits. It targets Postgres.
//
// The transaction is opened (optionally READ ONLY), session settings are
// applied via applySessionSettings, the query runs through
// pathsqlx.PathQueryTx on that same transaction, and the transaction is
// committed on success or rolled back on any error.
func RunQuery(ctx context.Context, pool *pathsqlx.DB, query string, params interface{}, hints map[string]string, opts QueryOptions) (interface{}, error) {
	tx, err := pool.BeginTxx(ctx, &sql.TxOptions{ReadOnly: opts.ReadOnly})
	if err != nil {
		return nil, err
	}

	// committed tracks whether Commit succeeded; the deferred rollback is a
	// no-op once it has.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := applySessionSettings(ctx, tx, opts); err != nil {
		return nil, err
	}

	result, err := pool.PathQueryTx(ctx, tx, query, params, hints)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true
	return result, nil
}
