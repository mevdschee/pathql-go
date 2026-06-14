package db

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/mevdschee/pathsqlx"
)

// QueryOptions configures how RunQuery executes a query under Postgres
// row-level security: whether to use a read-only transaction, and the optional
// transaction-local resource limits. The caller's identity is the connected
// database role (current_user), so there is no session variable to bind.
type QueryOptions struct {
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

// applySessionSettings applies the transaction-local resource limits from opts
// to tx using the function form of SET LOCAL (set_config(..., true)), which,
// unlike a bare SET, accepts bound parameters. It is factored out of RunQuery
// so it can be unit-tested against a recording fake driver without a real
// schema.
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
