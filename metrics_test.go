package main

import (
	"sync"
	"testing"
)

func TestTopQueriesRecordAndTop(t *testing.T) {
	tq := NewTopQueries(10)
	tq.Record("a", 10)
	tq.Record("a", 20) // a: count 2, total 30
	tq.Record("b", 5)
	tq.Record("b", 5)  // b: count 2, total 10
	tq.Record("c", 50) // c: count 1, total 50

	top := tq.Top(10)
	if len(top) != 3 {
		t.Fatalf("expected 3 distinct queries, got %d", len(top))
	}

	// Ranked by accumulated duration, slowest total first.
	expected := []QueryStat{
		{Query: "c", Count: 1, TotalMs: 50},
		{Query: "a", Count: 2, TotalMs: 30},
		{Query: "b", Count: 2, TotalMs: 10},
	}
	for i, want := range expected {
		if top[i] != want {
			t.Errorf("position %d: expected %+v, got %+v", i, want, top[i])
		}
	}
}

func TestTopQueriesTopLimitsResults(t *testing.T) {
	tq := NewTopQueries(10)
	tq.Record("a", 100)
	tq.Record("b", 50)
	tq.Record("c", 10)

	top := tq.Top(2)
	if len(top) != 2 {
		t.Fatalf("expected Top(2) to return 2 entries, got %d", len(top))
	}
	if top[0].Query != "a" || top[1].Query != "b" {
		t.Errorf("expected [a, b], got [%s, %s]", top[0].Query, top[1].Query)
	}
}

func TestTopQueriesSortedByDurationDescending(t *testing.T) {
	tq := NewTopQueries(10)
	tq.Record("low", 3)
	tq.Record("high", 70)
	tq.Record("mid", 25)

	top := tq.Top(10)
	for i := 1; i < len(top); i++ {
		if top[i-1].TotalMs < top[i].TotalMs {
			t.Errorf("not sorted descending: %+v before %+v", top[i-1], top[i])
		}
	}
}

// TestTopQueriesCapacityBound verifies the tracker never stores more distinct
// queries than its capacity, regardless of how many distinct queries arrive.
func TestTopQueriesCapacityBound(t *testing.T) {
	const capacity = 5
	tq := NewTopQueries(capacity)
	for i := 0; i < 1000; i++ {
		tq.Record(string(rune('a'+i%26)), uint64(i%7))
	}

	top := tq.Top(1000)
	if len(top) > capacity {
		t.Fatalf("expected at most %d tracked queries, got %d", capacity, len(top))
	}
}

// TestTopQueriesEvictionInheritsMinDuration verifies the Space-Saving rule: when
// every slot is full, the entry with the lowest accumulated duration is evicted
// and the incoming query inherits its count and duration totals.
func TestTopQueriesEvictionInheritsMinDuration(t *testing.T) {
	tq := NewTopQueries(2)
	tq.Record("a", 30)
	tq.Record("b", 5) // slots now full, b has the lowest duration

	tq.Record("c", 10) // evict b (total 5), c inherits 5+10=15, count 1+1=2

	top := tq.Top(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 tracked queries, got %d", len(top))
	}

	got := map[string]QueryStat{}
	for _, qs := range top {
		got[qs.Query] = qs
	}
	if a := got["a"]; a.Count != 1 || a.TotalMs != 30 {
		t.Errorf("expected a{count:1, total:30}, got %+v", a)
	}
	if c := got["c"]; c.Count != 2 || c.TotalMs != 15 {
		t.Errorf("expected c{count:2, total:15} (inherited from b), got %+v", c)
	}
	if _, ok := got["b"]; ok {
		t.Errorf("expected b to be evicted, but it is still tracked")
	}
}

// TestTopQueriesHeavyDurationHitterRetained verifies the core Space-Saving
// guarantee: a query that accumulates far more duration than the others is never
// evicted, and its reported total is at least its true accumulated duration.
func TestTopQueriesHeavyDurationHitterRetained(t *testing.T) {
	tq := NewTopQueries(3)
	const hits = 100
	const slowMs = 100

	for i := 0; i < hits; i++ {
		tq.Record("slow", slowMs)
		// Interleave a stream of unique fast queries to pressure eviction.
		tq.Record("fast-"+string(rune(i)), 1)
	}

	top := tq.Top(1)
	if len(top) == 0 {
		t.Fatal("expected at least one tracked query")
	}
	if top[0].Query != "slow" {
		t.Errorf("expected slow query on top, got %q", top[0].Query)
	}
	if top[0].TotalMs < hits*slowMs {
		t.Errorf("expected slow total_ms >= %d (Space-Saving never underestimates), got %d", hits*slowMs, top[0].TotalMs)
	}
}

// TestTopQueriesConcurrentRecord exercises the mutex under concurrent writers.
// Keeping the distinct-query set within capacity means no eviction occurs, so
// both the counts and durations must sum exactly. Run with -race.
func TestTopQueriesConcurrentRecord(t *testing.T) {
	tq := NewTopQueries(10)
	const goroutines = 8
	const perGoroutine = 1000
	const durationMs = 2

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				tq.Record(string(rune('a'+i%5)), durationMs)
			}
		}()
	}
	wg.Wait()

	var totalCount, totalMs uint64
	for _, qs := range tq.Top(10) {
		totalCount += qs.Count
		totalMs += qs.TotalMs
	}
	wantCount := uint64(goroutines * perGoroutine)
	if totalCount != wantCount {
		t.Errorf("expected total count %d, got %d", wantCount, totalCount)
	}
	if wantMs := wantCount * durationMs; totalMs != wantMs {
		t.Errorf("expected total_ms %d, got %d", wantMs, totalMs)
	}
}
