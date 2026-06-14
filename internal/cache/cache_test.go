package cache

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestCache builds a small in-process embedded cache for tests.
func newTestCache(t *testing.T) Cache {
	t.Helper()
	c, err := NewEmbedded(8)
	if err != nil {
		t.Fatalf("NewEmbedded(8): %v", err)
	}
	return c
}

func TestSetGetRoundTrip(t *testing.T) {
	c := newTestCache(t)
	defer c.Close()

	key := "roundtrip:key"
	want := []byte("hello world")
	if err := c.Set(key, want, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok, err := c.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatalf("Get: expected ok=true for stored key")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get: got %q, want %q", got, want)
	}
}

func TestGetMiss(t *testing.T) {
	c := newTestCache(t)
	defer c.Close()

	got, ok, err := c.Get("miss:never-set")
	if err != nil {
		t.Fatalf("Get miss should not error, got %v", err)
	}
	if ok {
		t.Fatalf("Get miss: expected ok=false, got ok=true value=%q", got)
	}
	if got != nil {
		t.Fatalf("Get miss: expected nil value, got %q", got)
	}
}

func TestIncrementAccumulates(t *testing.T) {
	c := newTestCache(t)
	defer c.Close()

	key := "incr:accumulate"

	v, err := c.Increment(key, 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment #1: %v", err)
	}
	if v != 1 {
		t.Fatalf("Increment #1: got %d, want 1", v)
	}

	v, err = c.Increment(key, 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment #2: %v", err)
	}
	if v != 2 {
		t.Fatalf("Increment #2: got %d, want 2", v)
	}

	v, err = c.Increment(key, 5, time.Minute)
	if err != nil {
		t.Fatalf("Increment #3: %v", err)
	}
	if v != 7 {
		t.Fatalf("Increment #3: got %d, want 7", v)
	}
}

func TestIncrementWindowResets(t *testing.T) {
	c := newTestCache(t)
	defer c.Close()

	key := "incr:window"
	ttl := 100 * time.Millisecond

	v, err := c.Increment(key, 1, ttl)
	if err != nil {
		t.Fatalf("Increment in window: %v", err)
	}
	if v != 1 {
		t.Fatalf("Increment in window: got %d, want 1", v)
	}

	v, err = c.Increment(key, 1, ttl)
	if err != nil {
		t.Fatalf("Increment in window #2: %v", err)
	}
	if v != 2 {
		t.Fatalf("Increment in window #2: got %d, want 2", v)
	}

	// Wait for the window to expire fully (hard expiry == soft expiry in this
	// embedded config), then the counter must reset to delta.
	time.Sleep(250 * time.Millisecond)

	v, err = c.Increment(key, 1, ttl)
	if err != nil {
		t.Fatalf("Increment after expiry: %v", err)
	}
	if v != 1 {
		t.Fatalf("Increment after expiry: got %d, want 1 (window did not reset)", v)
	}
}

func TestIncrementConcurrent(t *testing.T) {
	c := newTestCache(t)
	defer c.Close()

	key := "incr:concurrent"
	const goroutines = 50
	const perGoroutine = 100

	var wg sync.WaitGroup
	var errCount int64
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				if _, err := c.Increment(key, 1, time.Minute); err != nil {
					atomic.AddInt64(&errCount, 1)
				}
			}
		}()
	}
	wg.Wait()

	if errCount != 0 {
		t.Fatalf("Increment returned %d errors across goroutines", errCount)
	}

	v, _, err := c.Get(key)
	if err != nil {
		t.Fatalf("Get after concurrent increments: %v", err)
	}
	got, err := c.Increment(key, 0, time.Minute)
	if err != nil {
		t.Fatalf("final Increment read-back: %v", err)
	}
	want := uint64(goroutines * perGoroutine)
	if got != want {
		t.Fatalf("concurrent sum: got %d (raw stored %q), want %d", got, v, want)
	}
}
