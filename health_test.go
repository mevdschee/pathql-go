package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestHealthChecker builds a healthChecker with a stub ping so the caching and
// HTTP behavior can be exercised without a database.
func newTestHealthChecker(ping func(ctx context.Context) error) *healthChecker {
	return &healthChecker{ping: ping}
}

func TestHealthEndpointReachable(t *testing.T) {
	hc := newTestHealthChecker(func(context.Context) error { return nil })
	rec := httptest.NewRecorder()
	hc.HealthEndpoint(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" || body["database"] != "up" {
		t.Errorf("expected status ok / database up, got %v", body)
	}
}

func TestHealthEndpointUnreachable(t *testing.T) {
	hc := newTestHealthChecker(func(context.Context) error { return errors.New("connection refused") })
	rec := httptest.NewRecorder()
	hc.HealthEndpoint(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "unavailable" || body["database"] != "down" {
		t.Errorf("expected status unavailable / database down, got %v", body)
	}
	// The underlying error must not leak to the client.
	if got := rec.Body.String(); strings.Contains(got, "connection refused") {
		t.Errorf("response leaked the underlying error: %s", got)
	}
}

// TestHealthCachesPing verifies that repeated probes within the TTL ping the
// database only once, so the endpoint cannot amplify load onto the database.
func TestHealthCachesPing(t *testing.T) {
	var pings int64
	hc := newTestHealthChecker(func(context.Context) error {
		atomic.AddInt64(&pings, 1)
		return nil
	})

	for i := 0; i < 5; i++ {
		if err := hc.dbReachable(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if got := atomic.LoadInt64(&pings); got != 1 {
		t.Fatalf("expected 1 ping within the TTL, got %d", got)
	}

	// Expire the cache and probe again: exactly one more ping.
	hc.mu.Lock()
	hc.checkedAt = time.Now().Add(-2 * healthCacheTTL)
	hc.mu.Unlock()
	if err := hc.dbReachable(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atomic.LoadInt64(&pings); got != 2 {
		t.Fatalf("expected 2 pings after cache expiry, got %d", got)
	}
}

// TestHealthHandlerChain checks the assembled handler responds and sets the
// security headers from its middleware chain.
func TestHealthHandlerChain(t *testing.T) {
	hc := newTestHealthChecker(func(context.Context) error { return nil })
	rec := httptest.NewRecorder()
	healthHandler(hc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected SecurityHeaders middleware to set X-Content-Type-Options")
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Errorf("expected RequestID middleware to set X-Request-Id")
	}
}
