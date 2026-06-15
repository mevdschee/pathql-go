package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/mevdschee/pathsqlx"
)

// --- recording fake driver -------------------------------------------------
//
// The recording driver captures the SQL text and bound arguments of every
// Exec/Query in order, and supports Begin/Commit/Rollback. It lets us assert
// exactly what session-setup statements applySessionSettings emits, and that
// values (the app user and the session-variable name) arrive as BOUND args
// rather than being string-concatenated into SQL.

type recordedStmt struct {
	query string
	args  []driver.Value
}

type recorder struct {
	mu        sync.Mutex
	stmts     []recordedStmt
	begins    int
	commits   int
	rollbacks int
	// failErr, when set, is returned by every Exec so a test can force a
	// session-setting failure and exercise the rollback path.
	failErr error
	// explainJSON, when set, is returned as the single column of a single row for
	// any query beginning with "EXPLAIN", so the cost-ceiling path can be exercised
	// without a real planner.
	explainJSON []byte
	// execAffected is the RowsAffected count every Exec reports, so the write
	// blast-radius cap (RunWrite) can be exercised without a real table.
	execAffected int64
}

func (r *recorder) record(query string, args []driver.Value) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]driver.Value, len(args))
	copy(cp, args)
	r.stmts = append(r.stmts, recordedStmt{query: query, args: cp})
}

func (r *recorder) snapshot() []recordedStmt {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedStmt, len(r.stmts))
	copy(out, r.stmts)
	return out
}

// global recorder shared by the single registered recording driver. Tests
// reset it before use. Access is serialized by the recorder's mutex.
var sharedRecorder = &recorder{}

type recConn struct{ rec *recorder }

func (c recConn) Prepare(query string) (driver.Stmt, error) {
	return recStmt{rec: c.rec, query: query}, nil
}
func (c recConn) Close() error { return nil }
func (c recConn) Begin() (driver.Tx, error) {
	c.rec.mu.Lock()
	c.rec.begins++
	c.rec.mu.Unlock()
	return recTx{rec: c.rec}, nil
}

// BeginTx satisfies driver.ConnBeginTx so database/sql can open read-only
// transactions (BeginTxx with TxOptions{ReadOnly: true}). The options are
// accepted but not otherwise interpreted by this fake.
func (c recConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.rec.mu.Lock()
	c.rec.begins++
	c.rec.mu.Unlock()
	return recTx{rec: c.rec}, nil
}

type recTx struct{ rec *recorder }

func (t recTx) Commit() error {
	t.rec.mu.Lock()
	t.rec.commits++
	t.rec.mu.Unlock()
	return nil
}
func (t recTx) Rollback() error {
	t.rec.mu.Lock()
	t.rec.rollbacks++
	t.rec.mu.Unlock()
	return nil
}

type recStmt struct {
	rec   *recorder
	query string
}

func (s recStmt) Close() error  { return nil }
func (s recStmt) NumInput() int { return -1 }

func (s recStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.rec.record(s.query, args)
	s.rec.mu.Lock()
	fe := s.rec.failErr
	s.rec.mu.Unlock()
	if fe != nil {
		return nil, fe
	}
	s.rec.mu.Lock()
	n := s.rec.execAffected
	s.rec.mu.Unlock()
	return driver.RowsAffected(n), nil
}

func (s recStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.rec.record(s.query, args)
	s.rec.mu.Lock()
	ej := s.rec.explainJSON
	s.rec.mu.Unlock()
	if ej != nil && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s.query)), "EXPLAIN") {
		return &recRows{cols: []string{"QUERY PLAN"}, rows: [][]driver.Value{{ej}}}, nil
	}
	return &recRows{}, nil
}

// recRows is a result set the fake serves. With no cols it presents a single
// "set_config" column and no rows (the default, for the SELECT set_config calls);
// EXPLAIN queries get a one-row "QUERY PLAN" set carrying the recorder's plan JSON.
type recRows struct {
	cols []string
	rows [][]driver.Value
	pos  int
}

func (r *recRows) Columns() []string {
	if r.cols == nil {
		return []string{"set_config"}
	}
	return r.cols
}
func (r *recRows) Close() error { return nil }
func (r *recRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.pos])
	r.pos++
	return nil
}

type recDriver struct{ rec *recorder }

func (d recDriver) Open(name string) (driver.Conn, error) {
	return recConn{rec: d.rec}, nil
}

const recDriverName = "dbtestrecorder"

func init() {
	sql.Register(recDriverName, recDriver{rec: sharedRecorder})
}

// openRecordingTx resets the shared recorder, opens an sqlx.DB on the
// recording driver and begins a transaction on it.
func openRecordingTx(t *testing.T, readOnly bool) (*sqlx.Tx, *recorder, func()) {
	t.Helper()
	sharedRecorder.mu.Lock()
	sharedRecorder.stmts = nil
	sharedRecorder.begins = 0
	sharedRecorder.commits = 0
	sharedRecorder.rollbacks = 0
	sharedRecorder.failErr = nil
	sharedRecorder.explainJSON = nil
	sharedRecorder.execAffected = 0
	sharedRecorder.mu.Unlock()

	sdb, err := sql.Open(recDriverName, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	xdb := sqlx.NewDb(sdb, recDriverName)
	tx, err := xdb.BeginTxx(context.Background(), &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		t.Fatalf("BeginTxx: %v", err)
	}
	cleanup := func() {
		_ = tx.Rollback()
		_ = xdb.Close()
	}
	return tx, sharedRecorder, cleanup
}

// --- applySessionSettings tests --------------------------------------------

func TestApplySessionSettings_Full(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, true)
	defer cleanup()

	opts := QueryOptions{
		ReadOnly:         true,
		StatementTimeout: 5 * time.Second,
		IdleInTxTimeout:  3 * time.Second,
		WorkMemKB:        2048,
	}
	if err := applySessionSettings(context.Background(), tx, opts); err != nil {
		t.Fatalf("applySessionSettings: %v", err)
	}

	stmts := rec.snapshot()
	if len(stmts) != 3 {
		t.Fatalf("expected 3 statements, got %d: %+v", len(stmts), stmts)
	}

	// Each limit is set via the bound function form, in a fixed order, with the
	// GUC name and value both passed as bound arguments (never concatenated).
	want := []struct{ name, value string }{
		{"statement_timeout", "5000"},
		{"idle_in_transaction_session_timeout", "3000"},
		{"work_mem", "2048"},
	}
	for i, w := range want {
		if stmts[i].query != "SELECT set_config($1, $2, true)" {
			t.Errorf("stmt[%d] query = %q", i, stmts[i].query)
		}
		if len(stmts[i].args) != 2 {
			t.Fatalf("stmt[%d] args = %+v", i, stmts[i].args)
		}
		if got := stmts[i].args[0]; got != w.name {
			t.Errorf("stmt[%d] arg0 = %v, want %s", i, got, w.name)
		}
		if got := stmts[i].args[1]; got != w.value {
			t.Errorf("stmt[%d] arg1 = %v, want %q", i, got, w.value)
		}
	}
}

func TestApplySessionSettings_TimeoutOnly(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, true)
	defer cleanup()

	opts := QueryOptions{StatementTimeout: 250 * time.Millisecond}
	if err := applySessionSettings(context.Background(), tx, opts); err != nil {
		t.Fatalf("applySessionSettings: %v", err)
	}
	stmts := rec.snapshot()
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(stmts), stmts)
	}
	if stmts[0].args[0] != "statement_timeout" || stmts[0].args[1] != "250" {
		t.Errorf("timeout stmt args = %+v, want [statement_timeout 250]", stmts[0].args)
	}
}

func TestApplySessionSettings_NoneWhenEmpty(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, false)
	defer cleanup()

	cases := []QueryOptions{
		{},               // all zero: no limits to apply
		{ReadOnly: true}, // read-only affects the tx, not the session settings
	}
	for i, opts := range cases {
		// reset recorder between sub-cases
		rec.mu.Lock()
		rec.stmts = nil
		rec.mu.Unlock()
		if err := applySessionSettings(context.Background(), tx, opts); err != nil {
			t.Fatalf("case %d applySessionSettings: %v", i, err)
		}
		if got := rec.snapshot(); len(got) != 0 {
			t.Errorf("case %d: expected no statements, got %+v", i, got)
		}
	}
}

// --- RunQuery transaction lifecycle (no real schema) -----------------------
//
// RunQuery ultimately calls PathQueryTx which needs a real schema, so we only
// exercise the begin/settings/rollback path here by forcing a session setting to
// fail, which must roll back the transaction without committing.

func TestRunQuery_RollsBackOnSettingsError(t *testing.T) {
	sharedRecorder.mu.Lock()
	sharedRecorder.stmts = nil
	sharedRecorder.begins = 0
	sharedRecorder.commits = 0
	sharedRecorder.rollbacks = 0
	sharedRecorder.failErr = errors.New("set_config failed")
	sharedRecorder.mu.Unlock()
	t.Cleanup(func() {
		sharedRecorder.mu.Lock()
		sharedRecorder.failErr = nil
		sharedRecorder.mu.Unlock()
	})

	sdb, err := sql.Open(recDriverName, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	pool := pathsqlx.NewDb(sdb, recDriverName)
	t.Cleanup(func() { _ = pool.DB.DB.Close() })

	// A statement timeout makes applySessionSettings issue a set_config, which the
	// fake driver fails, so RunQuery must roll back without committing.
	opts := QueryOptions{StatementTimeout: time.Second}
	_, err = RunQuery(context.Background(), pool, "SELECT 1", nil, nil, opts)
	if err == nil {
		t.Fatal("expected error from failing session setting, got nil")
	}
	sharedRecorder.mu.Lock()
	defer sharedRecorder.mu.Unlock()
	if sharedRecorder.begins != 1 {
		t.Errorf("begins = %d, want 1", sharedRecorder.begins)
	}
	if sharedRecorder.commits != 0 {
		t.Errorf("commits = %d, want 0 (must not commit on error)", sharedRecorder.commits)
	}
	if sharedRecorder.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1", sharedRecorder.rollbacks)
	}
}

// --- optional live Postgres end-to-end probe -------------------------------
//
// Skips cleanly when no DB is reachable. Requires PATHQL_TEST_DSN to be set to
// a Postgres DSN; otherwise the test is skipped.
func TestRunQuery_LivePostgres(t *testing.T) {
	dsn := os.Getenv("PATHQL_TEST_DSN")
	if dsn == "" {
		t.Skip("PATHQL_TEST_DSN not set; skipping live Postgres test")
	}
	pool, err := OpenPool("postgres", dsn, 4, 2, time.Minute)
	if err != nil {
		t.Skipf("OpenPool: %v", err)
	}
	t.Cleanup(func() { _ = Close(pool) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Ping(ctx, pool); err != nil {
		t.Skipf("Postgres not reachable: %v", err)
	}

	opts := QueryOptions{
		ReadOnly:         true,
		StatementTimeout: 5 * time.Second,
	}
	res, err := RunQuery(ctx, pool,
		`SELECT current_user AS "$.user"`, nil, nil, opts)
	if err != nil {
		t.Fatalf("RunQuery: %v", err)
	}
	t.Logf("live result: %#v", res)
}

// --- proactive cost ceiling ------------------------------------------------

func TestParsePlanEstimate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		raw := []byte(`[{"Plan":{"Node Type":"Seq Scan","Total Cost":1234.56,"Plan Rows":9000}}]`)
		est, err := parsePlanEstimate(raw)
		if err != nil {
			t.Fatalf("parsePlanEstimate: %v", err)
		}
		if est.Cost != 1234.56 {
			t.Errorf("Cost = %v, want 1234.56", est.Cost)
		}
		if est.Rows != 9000 {
			t.Errorf("Rows = %v, want 9000", est.Rows)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, err := parsePlanEstimate([]byte("not json")); err == nil {
			t.Error("expected error for malformed JSON")
		}
	})
	t.Run("empty array", func(t *testing.T) {
		if _, err := parsePlanEstimate([]byte("[]")); err == nil {
			t.Error("expected error for empty plan array")
		}
	})
}

func TestCostCeilingError(t *testing.T) {
	est := planEstimate{Cost: 5000, Rows: 9000}
	cases := []struct {
		name     string
		maxCost  float64
		maxRows  int64
		wantOver bool
	}{
		{"both disabled", 0, 0, false},
		{"within both", 6000, 10000, false},
		{"over cost", 1000, 0, true},
		{"over rows", 0, 1000, true},
		{"cost ok rows over", 6000, 1000, true},
		{"exactly at cost is allowed", 5000, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := costCeilingError(est, tc.maxCost, tc.maxRows)
			if tc.wantOver {
				if !errors.Is(err, ErrQueryTooExpensive) {
					t.Errorf("err = %v, want ErrQueryTooExpensive", err)
				}
			} else if err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}

func TestEnforceCostCeiling_DisabledIssuesNoExplain(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, true)
	defer cleanup()

	if err := enforceCostCeiling(context.Background(), tx, "SELECT 1", nil, 0, 0); err != nil {
		t.Fatalf("enforceCostCeiling: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("expected no EXPLAIN to be issued when disabled, got %+v", got)
	}
}

func TestEnforceCostCeiling_RejectsOverBudget(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, true)
	defer cleanup()
	rec.mu.Lock()
	rec.explainJSON = []byte(`[{"Plan":{"Total Cost":5000.0,"Plan Rows":10}}]`)
	rec.mu.Unlock()

	// Cost over the bound.
	if err := enforceCostCeiling(context.Background(), tx, "SELECT 1", nil, 1000, 0); !errors.Is(err, ErrQueryTooExpensive) {
		t.Fatalf("over cost: err = %v, want ErrQueryTooExpensive", err)
	}
	// Within the bound: passes.
	if err := enforceCostCeiling(context.Background(), tx, "SELECT 1", nil, 1_000_000, 0); err != nil {
		t.Fatalf("within budget: err = %v, want nil", err)
	}
	// The EXPLAIN that was issued carried the FORMAT JSON prefix.
	var sawExplain bool
	for _, s := range rec.snapshot() {
		if strings.HasPrefix(s.query, "EXPLAIN (FORMAT JSON) ") {
			sawExplain = true
		}
	}
	if !sawExplain {
		t.Error("expected an EXPLAIN (FORMAT JSON) statement to be issued")
	}
}

// --- RunWrite (non-RETURNING path) -----------------------------------------
//
// The RETURNING path calls PathQueryTx, which needs a real schema, so the
// hermetic tests cover only the affected-count path here; RETURNING is covered
// by the e2e suite against a live Postgres.

// newRecordingPool resets the shared recorder, applies any per-test setup, and
// returns a pathsqlx pool on the recording driver.
func newRecordingPool(t *testing.T, setup func(r *recorder)) *pathsqlx.DB {
	t.Helper()
	sharedRecorder.mu.Lock()
	sharedRecorder.stmts = nil
	sharedRecorder.begins = 0
	sharedRecorder.commits = 0
	sharedRecorder.rollbacks = 0
	sharedRecorder.failErr = nil
	sharedRecorder.explainJSON = nil
	sharedRecorder.execAffected = 0
	if setup != nil {
		setup(sharedRecorder)
	}
	sharedRecorder.mu.Unlock()
	t.Cleanup(func() {
		sharedRecorder.mu.Lock()
		sharedRecorder.failErr = nil
		sharedRecorder.explainJSON = nil
		sharedRecorder.execAffected = 0
		sharedRecorder.mu.Unlock()
	})

	sdb, err := sql.Open(recDriverName, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	pool := pathsqlx.NewDb(sdb, recDriverName)
	t.Cleanup(func() { _ = pool.DB.DB.Close() })
	return pool
}

func TestRunWrite_NonReturningReturnsAffectedAndCommits(t *testing.T) {
	pool := newRecordingPool(t, func(r *recorder) { r.execAffected = 3 })

	res, err := RunWrite(context.Background(), pool,
		"UPDATE posts SET content = 'x'", nil, nil, QueryOptions{}, false)
	if err != nil {
		t.Fatalf("RunWrite: %v", err)
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map[string]interface{}", res)
	}
	if m["affected"] != int64(3) {
		t.Errorf("affected = %v, want 3", m["affected"])
	}
	sharedRecorder.mu.Lock()
	defer sharedRecorder.mu.Unlock()
	if sharedRecorder.commits != 1 {
		t.Errorf("commits = %d, want 1", sharedRecorder.commits)
	}
	if sharedRecorder.rollbacks != 0 {
		t.Errorf("rollbacks = %d, want 0", sharedRecorder.rollbacks)
	}
}

func TestRunWrite_AffectedCapRollsBack(t *testing.T) {
	pool := newRecordingPool(t, func(r *recorder) { r.execAffected = 100 })

	opts := QueryOptions{MaxAffectedRows: 10}
	_, err := RunWrite(context.Background(), pool,
		"DELETE FROM posts", nil, nil, opts, false)
	if !errors.Is(err, ErrTooManyRowsAffected) {
		t.Fatalf("err = %v, want ErrTooManyRowsAffected", err)
	}
	sharedRecorder.mu.Lock()
	defer sharedRecorder.mu.Unlock()
	if sharedRecorder.commits != 0 {
		t.Errorf("commits = %d, want 0 (an over-cap write must not commit)", sharedRecorder.commits)
	}
	if sharedRecorder.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1", sharedRecorder.rollbacks)
	}
}

func TestRunWrite_AtCapCommits(t *testing.T) {
	pool := newRecordingPool(t, func(r *recorder) { r.execAffected = 10 })

	// Exactly at the cap is allowed (the cap rejects only counts strictly above it).
	opts := QueryOptions{MaxAffectedRows: 10}
	if _, err := RunWrite(context.Background(), pool,
		"DELETE FROM posts WHERE id < 11", nil, nil, opts, false); err != nil {
		t.Fatalf("RunWrite at cap: %v", err)
	}
	sharedRecorder.mu.Lock()
	defer sharedRecorder.mu.Unlock()
	if sharedRecorder.commits != 1 {
		t.Errorf("commits = %d, want 1", sharedRecorder.commits)
	}
}

func TestRunWrite_RollsBackOnSettingsError(t *testing.T) {
	pool := newRecordingPool(t, func(r *recorder) { r.failErr = errors.New("set_config failed") })

	opts := QueryOptions{StatementTimeout: time.Second}
	if _, err := RunWrite(context.Background(), pool,
		"INSERT INTO posts (content) VALUES ('x')", nil, nil, opts, false); err == nil {
		t.Fatal("expected error from failing session setting, got nil")
	}
	sharedRecorder.mu.Lock()
	defer sharedRecorder.mu.Unlock()
	if sharedRecorder.commits != 0 {
		t.Errorf("commits = %d, want 0 (must not commit on error)", sharedRecorder.commits)
	}
	if sharedRecorder.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1", sharedRecorder.rollbacks)
	}
}

func TestRunQuery_RejectsOverBudgetBeforeExecuting(t *testing.T) {
	sharedRecorder.mu.Lock()
	sharedRecorder.stmts = nil
	sharedRecorder.begins = 0
	sharedRecorder.commits = 0
	sharedRecorder.rollbacks = 0
	sharedRecorder.failErr = nil
	sharedRecorder.explainJSON = []byte(`[{"Plan":{"Total Cost":9999.0,"Plan Rows":1000000}}]`)
	sharedRecorder.mu.Unlock()
	t.Cleanup(func() {
		sharedRecorder.mu.Lock()
		sharedRecorder.explainJSON = nil
		sharedRecorder.mu.Unlock()
	})

	sdb, err := sql.Open(recDriverName, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	pool := pathsqlx.NewDb(sdb, recDriverName)
	t.Cleanup(func() { _ = pool.DB.DB.Close() })

	opts := QueryOptions{MaxEstimatedRows: 100}
	_, err = RunQuery(context.Background(), pool, "SELECT 1", nil, nil, opts)
	if !errors.Is(err, ErrQueryTooExpensive) {
		t.Fatalf("err = %v, want ErrQueryTooExpensive", err)
	}
	sharedRecorder.mu.Lock()
	defer sharedRecorder.mu.Unlock()
	if sharedRecorder.commits != 0 {
		t.Errorf("commits = %d, want 0 (a rejected query must not run or commit)", sharedRecorder.commits)
	}
	if sharedRecorder.rollbacks != 1 {
		t.Errorf("rollbacks = %d, want 1", sharedRecorder.rollbacks)
	}
}
