package db

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mevdschee/pathsqlx"
)

// fakeOpener returns a pool opener that ignores the requested driver and opens
// against the in-package fakeDriverName instead, so RolePools tests never need
// a real database. pathsqlx.Open is lazy (no ping), so no connection is dialed
// as long as the tests never run a query. The captured dsns slice records every
// DSN the manager built, letting a test assert the role was interpolated.
func fakeOpener(dsns *[]string) func(driver, dsn string) (*pathsqlx.DB, error) {
	var mu sync.Mutex
	return func(_, dsn string) (*pathsqlx.DB, error) {
		mu.Lock()
		*dsns = append(*dsns, dsn)
		mu.Unlock()
		return pathsqlx.Open(fakeDriverName, dsn)
	}
}

func newTestPools(t *testing.T, maxTotal, warmLimit int, defaults PoolParams) (*RolePools, *[]string) {
	t.Helper()
	dsns := &[]string{}
	p, err := NewRolePoolsWithOpener(fakeDriverName, "host=db dbname=pathql sslmode=disable", maxTotal, warmLimit, defaults, fakeOpener(dsns))
	if err != nil {
		t.Fatalf("NewRolePoolsWithOpener returned error: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, dsns
}

func TestRoleDSN(t *testing.T) {
	const base = "host=db dbname=pathql sslmode=disable"
	tests := []struct {
		name    string
		role    string
		want    string
		wantErr bool
	}{
		{name: "simple", role: "pathql_r_42", want: base + " user=pathql_r_42"},
		{name: "leading underscore", role: "_admin", want: base + " user=_admin"},
		{name: "alnum body", role: "Role9", want: base + " user=Role9"},
		{name: "empty", role: "", wantErr: true},
		{name: "leading digit", role: "9role", wantErr: true},
		{name: "space", role: "ro le", wantErr: true},
		{name: "injection", role: "r sslmode=disable", wantErr: true},
		{name: "hyphen", role: "role-1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := roleDSN(base, tc.role)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("roleDSN(%q) error = nil, want error", tc.role)
				}
				return
			}
			if err != nil {
				t.Fatalf("roleDSN(%q) unexpected error: %v", tc.role, err)
			}
			if got != tc.want {
				t.Errorf("roleDSN(%q) = %q, want %q", tc.role, got, tc.want)
			}
		})
	}
}

func TestNewRolePoolsValidation(t *testing.T) {
	tests := []struct {
		name     string
		baseDSN  string
		maxTotal int
		wantErr  bool
	}{
		{name: "ok", baseDSN: "host=db", maxTotal: 1},
		{name: "empty dsn", baseDSN: "", maxTotal: 1, wantErr: true},
		{name: "zero backends", baseDSN: "host=db", maxTotal: 0, wantErr: true},
		{name: "negative backends", baseDSN: "host=db", maxTotal: -3, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewRolePools(fakeDriverName, tc.baseDSN, tc.maxTotal, 8, PoolParams{MaxOpen: 1})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewRolePools error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRolePools unexpected error: %v", err)
			}
			t.Cleanup(func() { _ = p.Close() })
		})
	}
}

func TestAcquireReturnsUsablePool(t *testing.T) {
	p, dsns := newTestPools(t, 4, 8, PoolParams{MaxOpen: 7, MaxIdle: 3})

	pool, release, err := p.Acquire(context.Background(), "pathql_r_1")
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	if pool == nil {
		t.Fatal("Acquire returned nil pool")
	}
	if release == nil {
		t.Fatal("Acquire returned nil release")
	}
	if got := pool.DB.DB.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7 (defaults applied)", got)
	}
	if len(*dsns) != 1 || (*dsns)[0] != "host=db dbname=pathql sslmode=disable user=pathql_r_1" {
		t.Errorf("opener saw dsns %v, want one entry ending in user=pathql_r_1", *dsns)
	}

	// A second Acquire for the same role reuses the pool (no new open).
	pool2, release2, err := p.Acquire(context.Background(), "pathql_r_1")
	if err != nil {
		t.Fatalf("second Acquire returned error: %v", err)
	}
	if pool2 != pool {
		t.Error("second Acquire for same role returned a different pool")
	}
	if len(*dsns) != 1 {
		t.Errorf("second Acquire opened a new pool: dsns = %v", *dsns)
	}
	release()
	release2()
}

func TestAcquireRejectsInvalidRole(t *testing.T) {
	p, _ := newTestPools(t, 2, 8, PoolParams{MaxOpen: 1})
	pool, release, err := p.Acquire(context.Background(), "bad role")
	if err == nil {
		t.Fatal("Acquire with invalid role returned nil error")
	}
	if pool != nil || release != nil {
		t.Error("Acquire with invalid role returned non-nil pool or release")
	}
	// The semaphore must not have leaked a slot: both slots remain free.
	if len(p.sem) != 0 {
		t.Errorf("semaphore holds %d slots after rejected Acquire, want 0", len(p.sem))
	}
}

func TestAcquireBlocksOnSemaphore(t *testing.T) {
	// One global backend slot. The first Acquire takes it; the second must
	// block until the first releases.
	p, _ := newTestPools(t, 1, 8, PoolParams{MaxOpen: 1, MaxIdle: 1})

	_, release1, err := p.Acquire(context.Background(), "role_a")
	if err != nil {
		t.Fatalf("first Acquire returned error: %v", err)
	}

	// Prove the second Acquire blocks: with a short timeout it must fail.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err = p.Acquire(ctx, "role_b")
	if err == nil {
		t.Fatal("second concurrent Acquire succeeded while slot was held, want it to block and time out")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("blocked Acquire error = %v, want context.DeadlineExceeded", err)
	}

	// Now prove it unblocks once the slot is released. Kick off a blocking
	// Acquire, then release the first slot and expect the second to complete.
	got := make(chan error, 1)
	go func() {
		_, release2, aerr := p.Acquire(context.Background(), "role_b")
		if release2 != nil {
			release2()
		}
		got <- aerr
	}()

	// Give the goroutine a moment to reach the blocking select, then free the slot.
	time.Sleep(20 * time.Millisecond)
	release1()

	select {
	case aerr := <-got:
		if aerr != nil {
			t.Fatalf("Acquire after release returned error: %v", aerr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire did not unblock after the slot was released")
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	p, _ := newTestPools(t, 1, 8, PoolParams{MaxOpen: 1})
	_, release, err := p.Acquire(context.Background(), "role_a")
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	release()
	release() // second call must not under-flow the semaphore or panic.
	if len(p.sem) != 0 {
		t.Errorf("semaphore holds %d slots after double release, want 0", len(p.sem))
	}
	// The slot is free, so a fresh Acquire succeeds immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, release2, err := p.Acquire(ctx, "role_a")
	if err != nil {
		t.Fatalf("Acquire after double release returned error: %v", err)
	}
	release2()
}

func TestAppliesConfiguredDefaults(t *testing.T) {
	p, _ := newTestPools(t, 4, 8, PoolParams{MaxOpen: 7, MaxIdle: 3})

	_, release, err := p.Acquire(context.Background(), "role_a")
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	release()

	if got := p.Stats()["role_a"].MaxOpenConnections; got != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7 (the configured default)", got)
	}
}

func TestWarmLRUCoolsDownLeastRecentlyUsed(t *testing.T) {
	// warmLimit of 2: once a third role is acquired, the least-recently-used
	// pool must be cooled down (MaxIdleConns set to 0) but not evicted.
	p, _ := newTestPools(t, 10, 2, PoolParams{MaxOpen: 5, MaxIdle: 3})

	acquire := func(role string) {
		_, release, err := p.Acquire(context.Background(), role)
		if err != nil {
			t.Fatalf("Acquire(%q) returned error: %v", role, err)
		}
		release()
	}

	// Acquire a, then b, then c, each at a distinct time so the LRU order is
	// deterministic. After c, role_a is the least-recently-used and must cool.
	acquire("role_a")
	time.Sleep(2 * time.Millisecond)
	acquire("role_b")
	time.Sleep(2 * time.Millisecond)
	acquire("role_c")

	stats := p.Stats()
	if len(stats) != 3 {
		t.Fatalf("expected 3 live pools, got %d", len(stats))
	}
	if got := stats["role_a"].MaxOpenConnections; got != 5 {
		t.Errorf("cooled pool must keep MaxOpen (not be evicted): role_a MaxOpen = %d, want 5", got)
	}
	if !p.pools["role_a"].cooledDown {
		t.Error("role_a should be cooled down (least recently used past warmLimit)")
	}
	if p.pools["role_b"].cooledDown {
		t.Error("role_b should remain warm")
	}
	if p.pools["role_c"].cooledDown {
		t.Error("role_c should remain warm (most recently used)")
	}

	// Re-acquiring role_a makes it most recently used, so it warms up again and
	// role_b becomes the coolest.
	time.Sleep(2 * time.Millisecond)
	acquire("role_a")
	if p.pools["role_a"].cooledDown {
		t.Error("role_a should warm up again after a fresh Acquire")
	}
	if !p.pools["role_b"].cooledDown {
		t.Error("role_b should now be the cooled-down (least recently used) pool")
	}
}

func TestRolesToCoolDown(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	mk := func(m map[string]int) map[string]time.Time {
		out := make(map[string]time.Time, len(m))
		for role, sec := range m {
			out[role] = base.Add(time.Duration(sec) * time.Second)
		}
		return out
	}
	tests := []struct {
		name      string
		lastUsed  map[string]time.Time
		warmLimit int
		want      []string
	}{
		{
			name:      "within limit cools none",
			lastUsed:  mk(map[string]int{"a": 1, "b": 2}),
			warmLimit: 2,
			want:      nil,
		},
		{
			name:      "one over cools the oldest",
			lastUsed:  mk(map[string]int{"a": 1, "b": 2, "c": 3}),
			warmLimit: 2,
			want:      []string{"a"},
		},
		{
			name:      "two over cools the two oldest",
			lastUsed:  mk(map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}),
			warmLimit: 2,
			want:      []string{"a", "b"},
		},
		{
			name:      "zero limit cools all",
			lastUsed:  mk(map[string]int{"a": 1, "b": 2}),
			warmLimit: 0,
			want:      []string{"a", "b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rolesToCoolDown(tc.lastUsed, tc.warmLimit)
			if len(got) != len(tc.want) {
				t.Fatalf("rolesToCoolDown = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("rolesToCoolDown = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestEvictRemovesPool(t *testing.T) {
	p, _ := newTestPools(t, 4, 8, PoolParams{MaxOpen: 5, MaxIdle: 2})
	_, release, err := p.Acquire(context.Background(), "role_a")
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	release()
	if _, ok := p.Stats()["role_a"]; !ok {
		t.Fatal("pool for role_a missing before Evict")
	}

	p.Evict("role_a")
	if _, ok := p.Stats()["role_a"]; ok {
		t.Error("pool for role_a still present after Evict")
	}
	// Evicting an unknown role is a no-op.
	p.Evict("role_nonexistent")
}

func TestCloseClosesAll(t *testing.T) {
	p, _ := newTestPools(t, 4, 8, PoolParams{MaxOpen: 5, MaxIdle: 2})
	for _, role := range []string{"role_a", "role_b", "role_c"} {
		_, release, err := p.Acquire(context.Background(), role)
		if err != nil {
			t.Fatalf("Acquire(%q) returned error: %v", role, err)
		}
		release()
	}
	if len(p.Stats()) != 3 {
		t.Fatalf("expected 3 pools before Close, got %d", len(p.Stats()))
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	if len(p.Stats()) != 0 {
		t.Errorf("expected 0 pools after Close, got %d", len(p.Stats()))
	}
}
