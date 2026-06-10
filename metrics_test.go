package main

import (
	"sync"
	"testing"
)

func TestTopQueriesRecordAndTop(t *testing.T) {
	tq := NewTopQueries(10)
	tq.Record("a")
	tq.Record("a")
	tq.Record("a")
	tq.Record("b")
	tq.Record("b")
	tq.Record("c")

	top := tq.Top(10)
	if len(top) != 3 {
		t.Fatalf("expected 3 distinct queries, got %d", len(top))
	}

	expected := []QueryCount{
		{Query: "a", Count: 3},
		{Query: "b", Count: 2},
		{Query: "c", Count: 1},
	}
	for i, want := range expected {
		if top[i] != want {
			t.Errorf("position %d: expected %+v, got %+v", i, want, top[i])
		}
	}
}

func TestTopQueriesTopLimitsResults(t *testing.T) {
	tq := NewTopQueries(10)
	for i := 0; i < 5; i++ {
		tq.Record("a")
	}
	for i := 0; i < 4; i++ {
		tq.Record("b")
	}
	for i := 0; i < 3; i++ {
		tq.Record("c")
	}

	top := tq.Top(2)
	if len(top) != 2 {
		t.Fatalf("expected Top(2) to return 2 entries, got %d", len(top))
	}
	if top[0].Query != "a" || top[1].Query != "b" {
		t.Errorf("expected [a, b], got [%s, %s]", top[0].Query, top[1].Query)
	}
}

func TestTopQueriesSortedByCountDescending(t *testing.T) {
	tq := NewTopQueries(10)
	tq.Record("low")
	for i := 0; i < 7; i++ {
		tq.Record("high")
	}
	for i := 0; i < 3; i++ {
		tq.Record("mid")
	}

	top := tq.Top(10)
	for i := 1; i < len(top); i++ {
		if top[i-1].Count < top[i].Count {
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
		tq.Record(string(rune('a' + i%26)))
	}

	top := tq.Top(1000)
	if len(top) > capacity {
		t.Fatalf("expected at most %d tracked queries, got %d", capacity, len(top))
	}
}

// TestTopQueriesEvictionInheritsMinCount verifies the Space-Saving rule: when
// every slot is full, the minimum-count query is evicted and the incoming query
// inherits min+1.
func TestTopQueriesEvictionInheritsMinCount(t *testing.T) {
	tq := NewTopQueries(2)
	tq.Record("a")
	tq.Record("a")
	tq.Record("a") // a -> 3
	tq.Record("b") // b -> 1, slots now full

	tq.Record("c") // full: evict b (min=1), c inherits 1+1=2

	top := tq.Top(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 tracked queries, got %d", len(top))
	}

	got := map[string]uint64{}
	for _, qc := range top {
		got[qc.Query] = qc.Count
	}
	if got["a"] != 3 {
		t.Errorf("expected a=3, got %d", got["a"])
	}
	if got["c"] != 2 {
		t.Errorf("expected c=2 (inherited min+1), got %d", got["c"])
	}
	if _, ok := got["b"]; ok {
		t.Errorf("expected b to be evicted, but it is still tracked")
	}
}

// TestTopQueriesHeavyHitterRetained verifies the core Space-Saving guarantee: a
// query that occurs far more often than total/capacity is never evicted, and its
// reported count is at least its true frequency.
func TestTopQueriesHeavyHitterRetained(t *testing.T) {
	tq := NewTopQueries(3)
	const hotHits = 100

	for i := 0; i < hotHits; i++ {
		tq.Record("hot")
		// Interleave a stream of unique cold queries to pressure eviction.
		tq.Record("cold-" + string(rune(i)))
	}

	top := tq.Top(1)
	if len(top) == 0 {
		t.Fatal("expected at least one tracked query")
	}
	if top[0].Query != "hot" {
		t.Errorf("expected hot query on top, got %q", top[0].Query)
	}
	if top[0].Count < hotHits {
		t.Errorf("expected hot count >= %d (Space-Saving never underestimates), got %d", hotHits, top[0].Count)
	}
}

// TestTopQueriesConcurrentRecord exercises the mutex under concurrent writers.
// Keeping the distinct-query set within capacity means no eviction occurs, so
// the counts must sum exactly to the number of Record calls. Run with -race.
func TestTopQueriesConcurrentRecord(t *testing.T) {
	tq := NewTopQueries(10)
	const goroutines = 8
	const perGoroutine = 1000

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				tq.Record(string(rune('a' + i%5)))
			}
		}()
	}
	wg.Wait()

	var total uint64
	for _, qc := range tq.Top(10) {
		total += qc.Count
	}
	want := uint64(goroutines * perGoroutine)
	if total != want {
		t.Errorf("expected total count %d, got %d", want, total)
	}
}
