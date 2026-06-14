package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
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
	return driver.RowsAffected(0), nil
}

func (s recStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.rec.record(s.query, args)
	return &recRows{}, nil
}

// recRows is an empty result set with a single column so set_config queries
// (run via Query, since they SELECT) have somewhere to scan from.
type recRows struct{ done bool }

func (r *recRows) Columns() []string { return []string{"set_config"} }
func (r *recRows) Close() error      { return nil }
func (r *recRows) Next(dest []driver.Value) error {
	return io.EOF
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
