package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
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
		AppUser:          "alice",
		SessionVariable:  "app.user",
		ReadOnly:         true,
		StatementTimeout: 5 * time.Second,
	}
	if err := applySessionSettings(context.Background(), tx, opts); err != nil {
		t.Fatalf("applySessionSettings: %v", err)
	}

	stmts := rec.snapshot()
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d: %+v", len(stmts), stmts)
	}

	// 1) statement_timeout first.
	if stmts[0].query != "SELECT set_config($1, $2, true)" {
		t.Errorf("stmt[0] query = %q", stmts[0].query)
	}
	if len(stmts[0].args) != 2 {
		t.Fatalf("stmt[0] args = %+v", stmts[0].args)
	}
	if got := stmts[0].args[0]; got != "statement_timeout" {
		t.Errorf("stmt[0] arg0 = %v, want statement_timeout", got)
	}
	if got := stmts[0].args[1]; got != "5000" {
		t.Errorf("stmt[0] arg1 = %v, want \"5000\" (ms as string)", got)
	}

	// 2) session variable second, with the var NAME and app user both BOUND.
	if stmts[1].query != "SELECT set_config($1, $2, true)" {
		t.Errorf("stmt[1] query = %q", stmts[1].query)
	}
	if len(stmts[1].args) != 2 {
		t.Fatalf("stmt[1] args = %+v", stmts[1].args)
	}
	if got := stmts[1].args[0]; got != "app.user" {
		t.Errorf("stmt[1] arg0 = %v, want app.user (bound)", got)
	}
	if got := stmts[1].args[1]; got != "alice" {
		t.Errorf("stmt[1] arg1 = %v, want alice (bound)", got)
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

func TestApplySessionSettings_SessionVarOnly(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, true)
	defer cleanup()

	opts := QueryOptions{AppUser: "bob", SessionVariable: "pathql.user"}
	if err := applySessionSettings(context.Background(), tx, opts); err != nil {
		t.Fatalf("applySessionSettings: %v", err)
	}
	stmts := rec.snapshot()
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(stmts), stmts)
	}
	if stmts[0].args[0] != "pathql.user" || stmts[0].args[1] != "bob" {
		t.Errorf("session var stmt args = %+v, want [pathql.user bob]", stmts[0].args)
	}
}

func TestApplySessionSettings_NoneWhenEmpty(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, false)
	defer cleanup()

	cases := []QueryOptions{
		{},                            // all zero
		{AppUser: "x"},                // no session variable
		{SessionVariable: "app.user"}, // no app user
		{StatementTimeout: 0, AppUser: "x", SessionVariable: ""}, // empty var
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

func TestApplySessionSettings_InvalidSessionVar(t *testing.T) {
	tx, rec, cleanup := openRecordingTx(t, false)
	defer cleanup()

	// A bad session-variable name with an app user set must be a hard error and
	// must NOT emit any session-variable statement (fail closed).
	opts := QueryOptions{AppUser: "alice", SessionVariable: "app.user;DROP TABLE"}
	if err := applySessionSettings(context.Background(), tx, opts); err == nil {
		t.Fatal("expected error for invalid session variable, got nil")
	}
	// No set_config for the session var should have been issued.
	for _, s := range rec.snapshot() {
		for _, a := range s.args {
			if a == "alice" {
				t.Errorf("app user was issued despite invalid session var: %+v", s)
			}
		}
	}
}

// --- session-variable validation -------------------------------------------

func TestValidateSessionVariable(t *testing.T) {
	valid := []string{"app.user", "pathql.user", "my_app.current_user", "_x.y", "a.b.c"}
	for _, v := range valid {
		if err := validateSessionVariable(v); err != nil {
			t.Errorf("validateSessionVariable(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"app_user",       // no dot
		"appuser",        // no dot
		"app.user;DROP",  // bad char ;
		"app.user'",      // bad char '
		"app.user space", // space
		"1app.user",      // leading digit
		".user",          // leading dot (no valid first char)
		"",               // empty
		"app.us er",      // embedded space
		"app-user.x",     // hyphen
	}
	for _, v := range invalid {
		if err := validateSessionVariable(v); err == nil {
			t.Errorf("validateSessionVariable(%q) = nil, want error", v)
		}
	}
}

// --- RunQuery transaction lifecycle (no real schema) -----------------------
//
// RunQuery ultimately calls PathQueryTx which needs a real schema, so we only
// exercise the begin/settings/rollback path here by forcing the validation to
// fail, which must roll back the transaction without committing.

func TestRunQuery_RollsBackOnSettingsError(t *testing.T) {
	sharedRecorder.mu.Lock()
	sharedRecorder.stmts = nil
	sharedRecorder.begins = 0
	sharedRecorder.commits = 0
	sharedRecorder.rollbacks = 0
	sharedRecorder.mu.Unlock()

	sdb, err := sql.Open(recDriverName, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	pool := pathsqlx.NewDb(sdb, recDriverName)
	t.Cleanup(func() { _ = pool.DB.DB.Close() })

	opts := QueryOptions{AppUser: "alice", SessionVariable: "no_dot_here"}
	_, err = RunQuery(context.Background(), pool, "SELECT 1", nil, nil, opts)
	if err == nil {
		t.Fatal("expected error from invalid session variable, got nil")
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
		AppUser:          "live-tester",
		SessionVariable:  "pathql.user",
		ReadOnly:         true,
		StatementTimeout: 5 * time.Second,
	}
	res, err := RunQuery(ctx, pool,
		`SELECT current_setting('pathql.user', true) AS "$.user"`, nil, nil, opts)
	if err != nil {
		t.Fatalf("RunQuery: %v", err)
	}
	t.Logf("live result: %#v", res)
}
