package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/mevdschee/pathql-go/internal/db"
	"github.com/mevdschee/pathql-go/internal/middleware"
	"github.com/mevdschee/pathsqlx"
)

// healthCacheTTL bounds how often GET /health actually pings the database. Rapid
// probes (or a flood of unauthenticated requests) reuse the cached result within
// this window, so the endpoint cannot be turned into a database-load amplifier.
const healthCacheTTL = 1 * time.Second

// healthPingTimeout caps a single readiness ping so a stalled database cannot
// hold the request open.
const healthPingTimeout = 2 * time.Second

// healthChecker answers readiness probes by pinging the database, memoizing the
// result for healthCacheTTL. The ping is injectable so the caching and HTTP
// behavior can be unit-tested without a real database.
type healthChecker struct {
	ping func(ctx context.Context) error

	mu        sync.Mutex
	checkedAt time.Time
	lastErr   error
	hasResult bool
}

// newHealthChecker returns a checker that pings pool. With identity_kind
// "login_role" this is the baseline connection, a fine proxy for "database
// reachable".
func newHealthChecker(pool *pathsqlx.DB) *healthChecker {
	return &healthChecker{
		ping: func(ctx context.Context) error { return db.Ping(ctx, pool) },
	}
}

// dbReachable returns nil when the database answered a ping within the cache
// window, or the ping error otherwise. The result is memoized for healthCacheTTL.
func (h *healthChecker) dbReachable(ctx context.Context) error {
	h.mu.Lock()
	if h.hasResult && time.Since(h.checkedAt) < healthCacheTTL {
		err := h.lastErr
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()

	// Ping outside the lock so a slow database does not serialize concurrent
	// probes; the brief window where several probes ping at once is harmless.
	pingCtx, cancel := context.WithTimeout(ctx, healthPingTimeout)
	defer cancel()
	err := h.ping(pingCtx)

	h.mu.Lock()
	h.checkedAt = time.Now()
	h.lastErr = err
	h.hasResult = true
	h.mu.Unlock()
	return err
}

// HealthEndpoint handles GET /health. It is unauthenticated so load balancers and
// orchestrators can probe it, and it is a readiness check: 200 when the database
// answered a recent ping, 503 when it did not (so traffic is kept away until the
// database is reachable). The body never reveals the underlying error.
func (h *healthChecker) HealthEndpoint(w http.ResponseWriter, req *http.Request) {
	status := http.StatusOK
	body := map[string]string{"status": "ok", "database": "up"}
	if err := h.dbReachable(req.Context()); err != nil {
		status = http.StatusServiceUnavailable
		body["status"] = "unavailable"
		body["database"] = "down"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// healthHandler wraps the health endpoint in a minimal middleware chain: panic
// recovery, security headers and a request id. It deliberately has no auth, no
// rate limiting and no concurrency cap so probes always get a prompt answer; the
// cached, bounded ping keeps the endpoint cheap regardless of request volume.
func healthHandler(hc *healthChecker) http.Handler {
	var h http.Handler = http.HandlerFunc(hc.HealthEndpoint)
	h = middleware.RequestID(h)
	h = middleware.SecurityHeaders(h)
	h = middleware.Recover(h)
	return h
}
