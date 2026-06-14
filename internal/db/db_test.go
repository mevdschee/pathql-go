package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"
)

// fakeConn is a no-op driver.Conn. It is never actually used to run queries in
// these tests because OpenPool uses lazy Open (no ping), so the pool never
// dials a real connection.
type fakeConn struct{}

func (fakeConn) Prepare(query string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (fakeConn) Close() error                              { return nil }
func (fakeConn) Begin() (driver.Tx, error)                 { return nil, driver.ErrSkip }

// fakeDriver is a minimal database/sql driver whose Open returns a no-op conn.
type fakeDriver struct{}

func (fakeDriver) Open(name string) (driver.Conn, error) { return fakeConn{}, nil }

// fakeDriverName is unique to avoid duplicate-register panics across packages.
const fakeDriverName = "dbtestfake"

func init() {
	sql.Register(fakeDriverName, fakeDriver{})
}

func TestOpenPoolAppliesCaps(t *testing.T) {
	pool, err := OpenPool(fakeDriverName, "", 7, 3, time.Minute)
	if err != nil {
		t.Fatalf("OpenPool returned error: %v", err)
	}
	if pool == nil {
		t.Fatal("OpenPool returned nil pool")
	}
	t.Cleanup(func() { _ = Close(pool) })

	if got := pool.DB.DB.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7", got)
	}
}

func TestOpenPoolUnknownDriver(t *testing.T) {
	pool, err := OpenPool("nosuchdriver-xyz", "", 1, 1, 0)
	if err == nil {
		t.Fatal("OpenPool with unknown driver returned nil error, want non-nil")
	}
	if pool != nil {
		t.Errorf("OpenPool with unknown driver returned non-nil pool: %v", pool)
	}
}

func TestClose(t *testing.T) {
	pool, err := OpenPool(fakeDriverName, "", 2, 1, 0)
	if err != nil {
		t.Fatalf("OpenPool returned error: %v", err)
	}
	if err := Close(pool); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestPingUnreachable(t *testing.T) {
	// The fake driver's conns are no-ops; Ping should not panic and should
	// return a (possibly nil) error without blocking forever.
	pool, err := OpenPool(fakeDriverName, "", 2, 1, 0)
	if err != nil {
		t.Fatalf("OpenPool returned error: %v", err)
	}
	t.Cleanup(func() { _ = Close(pool) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// We only assert it returns without hanging; the fake conn has no ping
	// support, so database/sql treats the connection as alive. Either outcome
	// (nil or error) is acceptable for the contract here.
	_ = Ping(ctx, pool)
}
