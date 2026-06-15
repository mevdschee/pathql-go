package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	// MaxEstimatedCost, when > 0, makes RunQuery EXPLAIN the query first (without
	// executing it) and reject it with ErrQueryTooExpensive if the planner's
	// estimated total cost exceeds this. 0 disables. PostgreSQL only.
	MaxEstimatedCost float64
	// MaxEstimatedRows, when > 0, rejects the query if the planner's estimated
	// output row count exceeds this (same EXPLAIN pre-check). 0 disables.
	MaxEstimatedRows int64
	// MaxAffectedRows, when > 0, is the write blast-radius cap: RunWrite rolls the
	// transaction back with ErrTooManyRowsAffected if a write affects (or, for a
	// RETURNING write, returns) more rows than this. 0 disables.
	MaxAffectedRows int64
}

// ErrTooManyRowsAffected is returned by RunWrite when a write affects more rows
// than QueryOptions.MaxAffectedRows allows. The write is rolled back before
// commit, so nothing persists. The wrapping error carries the actual count for
// server logs; callers map the sentinel to a 4xx with a generic client message.
var ErrTooManyRowsAffected = errors.New("write rejected: affected row count exceeds the configured limit")

// ErrQueryTooExpensive is returned by RunQuery when the proactive cost ceiling
// rejects a query: its PostgreSQL planner estimate (total cost or output rows,
// from EXPLAIN without execution) exceeds the configured bound. The wrapping
// error carries the specific estimate for server logs; callers map the sentinel
// to a 4xx with a generic client message.
var ErrQueryTooExpensive = errors.New("query rejected: estimated cost or row count exceeds the configured limit")

// planEstimate is the top plan node's estimate from EXPLAIN (FORMAT JSON).
type planEstimate struct {
	Cost float64
	Rows int64
}

// parsePlanEstimate extracts the top node's total cost and estimated row count
// from the document EXPLAIN (FORMAT JSON) returns: a one-element array whose
// element has a "Plan" object carrying "Total Cost" and "Plan Rows".
func parsePlanEstimate(raw []byte) (planEstimate, error) {
	var doc []struct {
		Plan struct {
			TotalCost float64 `json:"Total Cost"`
			PlanRows  float64 `json:"Plan Rows"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return planEstimate{}, fmt.Errorf("parse EXPLAIN output: %w", err)
	}
	if len(doc) == 0 {
		return planEstimate{}, fmt.Errorf("EXPLAIN output had no plan")
	}
	return planEstimate{Cost: doc[0].Plan.TotalCost, Rows: int64(doc[0].Plan.PlanRows)}, nil
}

// costCeilingError returns a wrapped ErrQueryTooExpensive when est exceeds either
// bound (a bound <= 0 is disabled), otherwise nil. Cost is checked before rows.
// The wrapped detail is for server logs only.
func costCeilingError(est planEstimate, maxCost float64, maxRows int64) error {
	if maxCost > 0 && est.Cost > maxCost {
		return fmt.Errorf("%w (estimated cost %.2f > %.2f)", ErrQueryTooExpensive, est.Cost, maxCost)
	}
	if maxRows > 0 && est.Rows > maxRows {
		return fmt.Errorf("%w (estimated rows %d > %d)", ErrQueryTooExpensive, est.Rows, maxRows)
	}
	return nil
}

// enforceCostCeiling runs EXPLAIN (FORMAT JSON) for query on tx and returns a
// wrapped ErrQueryTooExpensive if the planner's estimated cost or rows exceed the
// bounds. It executes nothing: plain EXPLAIN only, never ANALYZE. Both bounds
// <= 0 skip the check entirely (no EXPLAIN issued). Named parameters are bound
// exactly as pathsqlx binds the real query (sqlx.Named + Rebind), so EXPLAIN
// plans the same parameterized statement. PostgreSQL only; the caller enables it
// just for that driver, and a READ ONLY transaction further guarantees EXPLAIN
// cannot have side effects.
func enforceCostCeiling(ctx context.Context, tx *sqlx.Tx, query string, params interface{}, maxCost float64, maxRows int64) error {
	if maxCost <= 0 && maxRows <= 0 {
		return nil
	}
	if params == nil {
		params = map[string]interface{}{}
	}
	q, args, err := sqlx.Named(query, params)
	if err != nil {
		return err
	}
	q = tx.Rebind(q)
	var raw []byte
	if err := tx.QueryRowxContext(ctx, "EXPLAIN (FORMAT JSON) "+q, args...).Scan(&raw); err != nil {
		return err
	}
	est, err := parsePlanEstimate(raw)
	if err != nil {
		return err
	}
	return costCeilingError(est, maxCost, maxRows)
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

	// Proactive cost ceiling: EXPLAIN the query (no execution) and reject it
	// before running if the planner estimate exceeds the configured bound. Runs
	// inside the same transaction, after the timeouts are set so even planning is
	// bounded.
	if err := enforceCostCeiling(ctx, tx, query, params, opts.MaxEstimatedCost, opts.MaxEstimatedRows); err != nil {
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

// RunWrite executes a data-modifying statement (INSERT/UPDATE/DELETE, or a WITH
// wrapping one) inside a read-write transaction. It mirrors RunQuery - same
// transaction-local session settings (applySessionSettings) and the same
// proactive EXPLAIN cost ceiling (enforceCostCeiling) - and differs only in the
// transaction mode and the return shape:
//
//   - hasReturning true: the statement is run through pathsqlx, so the RETURNING
//     columns come back as JSON (a flat array by default, or shaped by hints).
//   - hasReturning false: the statement is executed and the result is
//     {"affected": N}, the rows-affected count.
//
// When opts.MaxAffectedRows > 0 the affected count is checked before commit and
// the transaction is rolled back with ErrTooManyRowsAffected if it is exceeded.
// The count is exact for the non-RETURNING path (RowsAffected) and for the
// default flat RETURNING shape (the number of returned rows); a RETURNING result
// reshaped by hints into a non-array cannot be counted post hoc, so for that case
// the cap relies on the pre-execution MaxEstimatedRows ceiling instead.
//
// PostgreSQL is the primary target (RETURNING and the EXPLAIN ceiling are
// Postgres features); the affected-count path is driver-agnostic.
func RunWrite(ctx context.Context, pool *pathsqlx.DB, query string, params interface{}, hints map[string]string, opts QueryOptions, hasReturning bool) (interface{}, error) {
	tx, err := pool.BeginTxx(ctx, &sql.TxOptions{ReadOnly: false})
	if err != nil {
		return nil, err
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := applySessionSettings(ctx, tx, opts); err != nil {
		return nil, err
	}

	if err := enforceCostCeiling(ctx, tx, query, params, opts.MaxEstimatedCost, opts.MaxEstimatedRows); err != nil {
		return nil, err
	}

	var result interface{}
	var affected int64
	knownAffected := false

	if hasReturning {
		result, err = pool.PathQueryTx(ctx, tx, query, params, hints)
		if err != nil {
			return nil, err
		}
		// The default (un-hinted) RETURNING result is a flat array; its length is
		// the number of rows the write touched. A hinted, reshaped result is not an
		// array, so the post-hoc count is skipped and the cap relies on the EXPLAIN
		// estimate.
		if rows, ok := result.([]interface{}); ok {
			affected = int64(len(rows))
			knownAffected = true
		}
	} else {
		p := params
		if p == nil {
			p = map[string]interface{}{}
		}
		q, args, nerr := sqlx.Named(query, p)
		if nerr != nil {
			return nil, nerr
		}
		q = tx.Rebind(q)
		res, eerr := tx.ExecContext(ctx, q, args...)
		if eerr != nil {
			return nil, eerr
		}
		affected, _ = res.RowsAffected()
		knownAffected = true
		result = map[string]interface{}{"affected": affected}
	}

	if opts.MaxAffectedRows > 0 && knownAffected && affected > opts.MaxAffectedRows {
		return nil, fmt.Errorf("%w (affected %d > %d)", ErrTooManyRowsAffected, affected, opts.MaxAffectedRows)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true
	return result, nil
}
