package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mevdschee/pathsqlx"

	"github.com/mevdschee/pathql-go/internal/auth"
	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
	"github.com/mevdschee/pathql-go/internal/db"
	"github.com/mevdschee/pathql-go/internal/middleware"
	"github.com/mevdschee/pathql-go/internal/roles"
	"github.com/mevdschee/pathql-go/internal/sqlgate"
)

// cfg holds the loaded server configuration.
var cfg *config.Config

// pool is the shared connection pool. With identity_kind "none" it serves every
// caller query (the simple, no-RLS model). With identity_kind "login_role" it is
// the baseline connection (authenticated as roles.baseline_role) used for
// auth-table lookups, admin CRUD and catalog reads, and caller queries run on
// rolePools instead.
var pool *pathsqlx.DB

// rolePools is the per-role connection manager, non-nil only with identity_kind
// "login_role". Each caller query then runs on a connection authenticated as the
// caller's own database role.
var rolePools *db.RolePools

// sharedCache is the abuse-protection / JWKS cache built at startup and shared
// by the rate limiter and the JWT authenticator. It is closed on shutdown.
var sharedCache cache.Cache

// Metrics holds request metrics
type Metrics struct {
	status200         uint64
	status400         uint64
	status500         uint64
	statusOther       uint64
	latencyLt1ms      uint64
	latencyLt5ms      uint64
	latencyLt10ms     uint64
	latencyLt50ms     uint64
	latencyLt100ms    uint64
	latencyLt500ms    uint64
	latencyLt1000ms   uint64
	latencyLt5000ms   uint64
	latencyLt10000ms  uint64
	latencyGte10000ms uint64
	// reject429 / reject503 count abuse-protection rejections (rate limit and
	// per-user caps -> 429; global in-flight cap -> 503) observed by the metrics
	// middleware, which sits outside those limiters in the chain.
	reject429 uint64
	reject503 uint64
}

var metrics Metrics

// topQueriesCapacity bounds how many distinct queries the toplist tracks.
// Memory use is bounded to this many query strings regardless of traffic.
const topQueriesCapacity = 1000

// QueryStat is one entry in the queries toplist: how often a query ran and the
// total time spent running it.
type QueryStat struct {
	Query   string `json:"query"`
	Count   uint64 `json:"count"`
	TotalMs uint64 `json:"total_ms"`
}

// queryStat is the internal mutable counter pair for one tracked query.
type queryStat struct {
	count   uint64
	totalMs uint64
}

// TopQueries tracks the queries that consume the most total time using the
// Space-Saving algorithm (Metwally et al., 2005). It keeps at most `capacity`
// entries; when a new query arrives and every slot is taken, the slot with the
// lowest accumulated duration is evicted and the new query inherits that slot's
// totals so a heavy hitter can't be underreported. This yields an accurate
// top-K by total duration in bounded memory without storing every distinct query.
type TopQueries struct {
	mu       sync.Mutex
	capacity int
	stats    map[string]*queryStat
}

// NewTopQueries returns a Space-Saving tracker holding up to capacity entries.
func NewTopQueries(capacity int) *TopQueries {
	return &TopQueries{
		capacity: capacity,
		stats:    make(map[string]*queryStat, capacity),
	}
}

// Record adds one occurrence of query taking durationMs milliseconds.
func (t *TopQueries) Record(query string, durationMs uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.stats[query]; ok {
		s.count++
		s.totalMs += durationMs
		return
	}
	if len(t.stats) < t.capacity {
		t.stats[query] = &queryStat{count: 1, totalMs: durationMs}
		return
	}

	// All slots full: evict the query with the lowest accumulated duration (the
	// value the toplist ranks by) and let the new one take its place, inheriting
	// the evicted totals so a heavy hitter can't be underreported. The linear
	// scan is O(capacity); fine for a metrics feature, swap in a stream-summary
	// list if it ever gets hot.
	var minQuery string
	var minTotalMs uint64 = math.MaxUint64
	for q, s := range t.stats {
		if s.totalMs < minTotalMs {
			minTotalMs = s.totalMs
			minQuery = q
		}
	}
	evicted := t.stats[minQuery]
	delete(t.stats, minQuery)
	t.stats[query] = &queryStat{
		count:   evicted.count + 1,
		totalMs: evicted.totalMs + durationMs,
	}
}

// Top returns the n queries with the highest accumulated duration, slowest
// total first.
func (t *TopQueries) Top(n int) []QueryStat {
	t.mu.Lock()
	list := make([]QueryStat, 0, len(t.stats))
	for q, s := range t.stats {
		list = append(list, QueryStat{Query: q, Count: s.count, TotalMs: s.totalMs})
	}
	t.mu.Unlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].TotalMs > list[j].TotalMs
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

var topQueries = NewTopQueries(topQueriesCapacity)

// topUsersCapacity bounds how many distinct app_user identities the per-user
// duration toplist tracks. Memory is bounded to this many identities.
const topUsersCapacity = 1000

// topUsers tracks accumulated request-handling time per authenticated app_user.
// It reuses the TopQueries Space-Saving engine; internally the QueryStat.Query
// field holds the app_user name, which is remapped to "user" in the metrics
// response (see UserStat).
var topUsers = NewTopQueries(topUsersCapacity)

// UserStat is one entry in the per-user duration toplist (top_users): the
// app_user, how many requests it made and the total time spent serving them.
type UserStat struct {
	User    string `json:"user"`
	Count   uint64 `json:"count"`
	TotalMs uint64 `json:"total_ms"`
}

// responseWriter wraps http.ResponseWriter to capture the status code and the
// number of bytes written. It counts bytes rather than buffering a copy of the
// body, so a large response is not duplicated in memory just for metrics.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// errResponseTooLarge is returned by cappedBuffer when an encoded response would
// exceed the configured max_response_bytes.
var errResponseTooLarge = errors.New("response exceeds max_response_bytes")

// cappedBuffer is an io.Writer that accumulates up to limit bytes and then fails
// with errResponseTooLarge. Encoding the response into it bounds both the encode
// buffer and the client payload, and lets an oversized result be rejected with a
// clean error before any bytes are sent. limit <= 0 means unlimited.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int64
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.limit > 0 && int64(c.buf.Len()+len(p)) > c.limit {
		return 0, errResponseTooLarge
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// Request is the data structure posted to the /pathql endpoint.
type Request struct {
	Query  string            `json:"query"`
	Params any               `json:"params"`
	Paths  map[string]string `json:"paths"`
}

// ErrorResponse is the data structure used to report pathql errors
type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// genericInternalError is the only thing a client ever sees on a 500. The real
// error is logged server-side; driver internals never reach the client.
const genericInternalError = "internal error"

// metricsMiddleware tracks request metrics and logs in verbose mode.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Milliseconds()

		// Track status code
		switch rw.statusCode {
		case 200:
			atomic.AddUint64(&metrics.status200, 1)
		case 400:
			atomic.AddUint64(&metrics.status400, 1)
		case 500:
			atomic.AddUint64(&metrics.status500, 1)
		case http.StatusTooManyRequests:
			atomic.AddUint64(&metrics.reject429, 1)
			atomic.AddUint64(&metrics.statusOther, 1)
		case http.StatusServiceUnavailable:
			atomic.AddUint64(&metrics.reject503, 1)
			atomic.AddUint64(&metrics.statusOther, 1)
		default:
			atomic.AddUint64(&metrics.statusOther, 1)
		}

		// Track latency bracket
		switch {
		case duration < 1:
			atomic.AddUint64(&metrics.latencyLt1ms, 1)
		case duration < 5:
			atomic.AddUint64(&metrics.latencyLt5ms, 1)
		case duration < 10:
			atomic.AddUint64(&metrics.latencyLt10ms, 1)
		case duration < 50:
			atomic.AddUint64(&metrics.latencyLt50ms, 1)
		case duration < 100:
			atomic.AddUint64(&metrics.latencyLt100ms, 1)
		case duration < 500:
			atomic.AddUint64(&metrics.latencyLt500ms, 1)
		case duration < 1000:
			atomic.AddUint64(&metrics.latencyLt1000ms, 1)
		case duration < 5000:
			atomic.AddUint64(&metrics.latencyLt5000ms, 1)
		case duration < 10000:
			atomic.AddUint64(&metrics.latencyLt10000ms, 1)
		default:
			atomic.AddUint64(&metrics.latencyGte10000ms, 1)
		}

		// Verbose logging
		if cfg != nil && cfg.Verbose {
			log.Printf("%s %d %d %dms\n",
				time.Now().Format(time.RFC3339),
				rw.statusCode,
				rw.bytesWritten,
				duration)
		}
	})
}

// MetricsEndpoint handles GET to /metrics. It is bound to the admin listener
// only: top_queries exposes raw query text, so it must never sit on the public
// port.
func MetricsEndpoint(w http.ResponseWriter, req *http.Request) {
	// Remap the per-user toplist (whose engine stores the name in QueryStat.Query)
	// to the user-shaped output.
	userTop := topUsers.Top(10)
	users := make([]UserStat, len(userTop))
	for i, s := range userTop {
		users[i] = UserStat{User: s.Query, Count: s.Count, TotalMs: s.TotalMs}
	}

	response := map[string]any{
		"status_codes": map[string]uint64{
			"200":   atomic.LoadUint64(&metrics.status200),
			"400":   atomic.LoadUint64(&metrics.status400),
			"500":   atomic.LoadUint64(&metrics.status500),
			"other": atomic.LoadUint64(&metrics.statusOther),
		},
		"latency_ms": map[string]uint64{
			"<1":      atomic.LoadUint64(&metrics.latencyLt1ms),
			"<5":      atomic.LoadUint64(&metrics.latencyLt5ms),
			"<10":     atomic.LoadUint64(&metrics.latencyLt10ms),
			"<50":     atomic.LoadUint64(&metrics.latencyLt50ms),
			"<100":    atomic.LoadUint64(&metrics.latencyLt100ms),
			"<500":    atomic.LoadUint64(&metrics.latencyLt500ms),
			"<1000":   atomic.LoadUint64(&metrics.latencyLt1000ms),
			"<5000":   atomic.LoadUint64(&metrics.latencyLt5000ms),
			"<10000":  atomic.LoadUint64(&metrics.latencyLt10000ms),
			">=10000": atomic.LoadUint64(&metrics.latencyGte10000ms),
		},
		"auth": map[string]uint64{
			"success": auth.AuthSuccessCount(),
			"failure": auth.AuthFailureCount(),
		},
		"rejections": map[string]uint64{
			"429": atomic.LoadUint64(&metrics.reject429),
			"503": atomic.LoadUint64(&metrics.reject503),
		},
		"top_queries": topQueries.Top(10),
		"top_users":   users,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// writeError writes a generic JSON error body with the given status. The real
// cause is logged server-side (with the request id) and never sent to the
// client, so database/driver internals do not leak.
func writeError(w http.ResponseWriter, r *http.Request, status int, clientMsg string, cause error) {
	if cause != nil {
		log.Printf("pathql: request %s: %d: %v", requestID(r, w), status, cause)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{"Error", clientMsg})
}

// requestID returns the X-Request-Id the RequestID middleware set on the
// response (falling back to any inbound value), for correlating logs.
func requestID(r *http.Request, w http.ResponseWriter) string {
	if id := w.Header().Get("X-Request-Id"); id != "" {
		return id
	}
	return r.Header.Get("X-Request-Id")
}

// PathQlEndpoint handles POST to /pathql. It runs the query against the shared
// pool and returns only generic errors to the client.
func PathQlEndpoint(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	request := Request{}

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		// Malformed body (or a body over the size cap): client error, generic
		// message. Do not echo the parser/driver detail.
		writeError(w, req, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if request.Query != "" {
		defer func() {
			topQueries.Record(request.Query, uint64(time.Since(start).Milliseconds()))
		}()
	}

	// Reject slice/array params - only maps are supported.
	if _, ok := request.Params.([]any); ok {
		writeError(w, req, http.StatusBadRequest, "params must be an object, not an array", nil)
		return
	}

	// Classify the statement and decide read vs write. When writes are disabled
	// (the default) the optional SQL gate is the only statement validator and
	// every query runs read-only. When writes are enabled, Classify routes the
	// request: it applies the gate's structural rules (single statement, no system
	// catalogs) itself and additionally distinguishes a read from a write, so a
	// write reaches the read-write path while reads stay read-only. Either way the
	// rejection reason describes the request shape, so it is safe to return.
	writesEnabled := cfg.WritesEnabled()
	var class sqlgate.Class
	var hasReturning bool
	if writesEnabled {
		c, cerr := sqlgate.Classify(request.Query)
		if cerr != nil {
			writeError(w, req, http.StatusBadRequest, cerr.Error(), cerr)
			return
		}
		class = c
		if class == sqlgate.ClassWrite {
			hasReturning = sqlgate.HasReturning(request.Query)
		}
	} else if err := sqlgate.Check(request.Query, sqlgate.Mode(cfg.Security.SQLGate)); err != nil {
		writeError(w, req, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Convert nil params to empty map for sqlx compatibility.
	params := request.Params
	if params == nil {
		params = map[string]any{}
	}

	// Convert nil paths to empty map for sqlx compatibility.
	paths := request.Paths
	if paths == nil {
		paths = map[string]string{}
	}

	// Resolve the authenticated principal (nil when auth is disabled).
	var principal *auth.Principal
	appUser := ""
	if p, ok := auth.FromContext(req.Context()); ok && p != nil {
		principal = p
		appUser = p.AppUser
		// Audit: log the authenticated identity with the request id for correlation.
		log.Printf("pathql: request %s: authenticated app_user=%q user_id=%d", requestID(req, w), p.AppUser, p.UserID)
		// Attribute the request-handling time to this identity for the top_users
		// metric. Same total-handler-time basis as the top_queries record above.
		defer func() {
			topUsers.Record(appUser, uint64(time.Since(start).Milliseconds()))
		}()
	}

	statementTimeout := time.Duration(cfg.Limits.MaxQueryMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(req.Context(), statementTimeout)
	defer cancel()

	opts := db.QueryOptions{
		ReadOnly:         cfg.Security.ReadOnly,
		StatementTimeout: statementTimeout,
		IdleInTxTimeout:  statementTimeout,
		WorkMemKB:        cfg.Limits.WorkMemKB,
	}
	// Proactive cost ceiling via EXPLAIN. PostgreSQL only (the plan JSON and the
	// EXPLAIN syntax are Postgres-specific), so only enable it for that driver.
	if cfg.Driver == "postgres" {
		opts.MaxEstimatedCost = cfg.Limits.MaxEstimatedCost
		opts.MaxEstimatedRows = cfg.Limits.MaxEstimatedRows
	}
	// Write blast-radius cap (driver-agnostic); only consulted on the write path.
	opts.MaxAffectedRows = cfg.Limits.MaxAffectedRows

	// Select the connection by identity model. With identity_kind "none" the
	// shared pool serves every query and there is no per-caller RLS binding. With
	// "login_role" the query runs on a connection authenticated as the caller's
	// own database role, so RLS policies see an unforgeable current_user.
	queryPool, release, ok := selectQueryPool(ctx, w, req, principal)
	if !ok {
		return
	}
	defer release()

	// Route by class. A write runs in a read-write transaction (RunWrite); a read
	// always runs READ ONLY. When writes are enabled the top-level read_only is
	// false (validation forbids combining it with writes = on), so force the read
	// path read-only here - enabling writes must never relax the read path.
	var response interface{}
	var err error
	if writesEnabled && class == sqlgate.ClassWrite {
		response, err = db.RunWrite(ctx, queryPool, request.Query, params, paths, opts, hasReturning)
	} else {
		readOpts := opts
		if writesEnabled {
			readOpts.ReadOnly = true
		}
		response, err = db.RunQuery(ctx, queryPool, request.Query, params, paths, readOpts)
	}
	if err != nil {
		// A timeout (Go-side or DB-side) is reported as 503 server-busy; any other
		// driver/query error is a generic 500. The real cause is logged
		// server-side only, never returned to the client.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeError(w, req, http.StatusServiceUnavailable, "query timed out", err)
			return
		}
		// Proactive cost ceiling rejected the query before running it. Generic
		// client message (the estimate/limit detail is logged server-side via the
		// wrapped cause, not returned, so data volume is not disclosed).
		if errors.Is(err, db.ErrQueryTooExpensive) {
			writeError(w, req, http.StatusBadRequest, "query rejected: estimated cost or row count exceeds the configured limit", err)
			return
		}
		// Write blast-radius cap: the write was rolled back before commit. Generic
		// message; the actual count is logged via the wrapped cause, not returned.
		if errors.Is(err, db.ErrTooManyRowsAffected) {
			writeError(w, req, http.StatusBadRequest, "write rejected: affected row count exceeds the configured limit", err)
			return
		}
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}

	// Encode into a size-capped buffer so an oversized result is rejected with a
	// clean error before any bytes reach the client, and the buffered amount stays
	// bounded by max_response_bytes.
	buf := &cappedBuffer{limit: cfg.Limits.MaxResponseBytes}
	if err := json.NewEncoder(buf).Encode(response); err != nil {
		if errors.Is(err, errResponseTooLarge) {
			writeError(w, req, http.StatusRequestEntityTooLarge, "response too large", err)
			return
		}
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf.Bytes())
}

// selectQueryPool returns the database pool a caller's read should run on under
// the configured identity model, plus a release func to call when the work is
// done (a no-op in shared mode). With identity_kind "none" it is the shared pool
// and there is no per-caller binding; with "login_role" it is the caller's own
// per-role pool, acquired against ctx, so RLS policies see an unforgeable
// current_user. On failure it writes the HTTP error itself and returns ok=false.
func selectQueryPool(ctx context.Context, w http.ResponseWriter, req *http.Request, principal *auth.Principal) (queryPool *pathsqlx.DB, release func(), ok bool) {
	if cfg.Security.IdentityKind != "login_role" {
		return pool, func() {}, true
	}
	if principal == nil {
		writeError(w, req, http.StatusUnauthorized, "authentication required", nil)
		return nil, nil, false
	}
	role, nameErr := roles.RoleName(cfg.Roles.Prefix, principal.UserID)
	if nameErr != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, nameErr)
		return nil, nil, false
	}
	rp, rel, acqErr := rolePools.Acquire(ctx, role)
	if acqErr != nil {
		if errors.Is(acqErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeError(w, req, http.StatusServiceUnavailable, "server busy", acqErr)
			return nil, nil, false
		}
		writeError(w, req, http.StatusInternalServerError, genericInternalError, acqErr)
		return nil, nil, false
	}
	return rp, rel, true
}

// buildAuthChain builds the authentication chain from the configured methods.
// It returns a nil chain when no methods are configured (auth disabled).
func buildAuthChain(c *config.Config) (*auth.Chain, error) {
	if len(c.Auth.Methods) == 0 {
		return nil, nil
	}
	store, err := auth.NewSQLUserStore(pool.DB, c.Security.AuthTablePrefix)
	if err != nil {
		return nil, err
	}
	var auths []auth.Authenticator
	for _, m := range c.Auth.Methods {
		switch m {
		case "apikey":
			auths = append(auths, auth.NewAPIKeyAuthenticator(store, c.Auth.APIKeyHeader))
		case "basic":
			auths = append(auths, auth.NewBasicAuthenticator(store))
		case "jwt":
			jwtAuth, err := auth.NewJWTAuthenticator(auth.JWTConfig{
				Algorithms:     c.Auth.JWTAlgorithms,
				Issuer:         c.Auth.JWTIssuer,
				Audience:       c.Auth.JWTAudience,
				UserClaim:      c.Auth.JWTUserClaim,
				HS256Secret:    []byte(c.Auth.JWTHS256Secret),
				JWKSURL:        c.Auth.JWTJWKSURL,
				JWKSTTL:        c.Cache.JWKSTTLDuration,
				RequireUserRow: c.Auth.RequireUserRow,
			}, store, sharedCache, http.DefaultClient)
			if err != nil {
				return nil, err
			}
			auths = append(auths, jwtAuth)
		}
	}
	return auth.NewChain(auths...), nil
}

// principalKey is the PerUserConcurrency key function: it limits per
// authenticated AppUser, returning "" (not limited) for unauthenticated
// requests so the per-user cap only applies once an identity is known.
func principalKey(r *http.Request) string {
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		return p.AppUser
	}
	return ""
}

// publicHandler assembles the middleware chain for the public /pathql route.
// Order, outer to inner (per SECURITY_PLAN section 5):
//
//	Recover -> SecurityHeaders -> [HSTS if TLS] -> CORS -> RequestID ->
//	RequireContentTypeJSON -> BodyLimit -> GlobalInflight -> RateLimitPerIP ->
//	metrics -> [auth if enabled] -> PerUserConcurrency -> PathQlEndpoint
//
// The per-user limiter sits AFTER auth so its key is the resolved AppUser.
func publicHandler(c *config.Config, chain *auth.Chain, theCache cache.Cache, trustedProxies []*net.IPNet) http.Handler {
	var h http.Handler = http.HandlerFunc(PathQlEndpoint)
	h = middleware.PerUserConcurrency(c.Limits.MaxConcurrentPerUser, principalKey)(h)
	// The metrics-only and admin-only principals may use only their own
	// endpoints: keep them off /pathql. Runs after auth (so the principal is
	// resolved) and before the per-user slot is taken.
	h = denyAppUser(c.Security.MetricsUser)(h)
	h = denyAppUser(c.Security.AdminUser)(h)
	if chain != nil {
		h = chain.Middleware(h)
	}
	// BruteForceLockout wraps auth so it can observe the 401 and count failures.
	h = middleware.BruteForceLockout(theCache, c.Limits.MaxAuthFailuresPerMin, trustedProxies)(h)
	h = metricsMiddleware(h)
	h = middleware.RateLimitPerIP(theCache, c.Limits.MaxRequestsPerMinIP, trustedProxies)(h)
	h = middleware.GlobalInflight(c.Limits.MaxConcurrentGlobal)(h)
	h = middleware.BodyLimit(c.Limits.MaxBodyBytes)(h)
	h = middleware.RequireContentTypeJSON(h)
	h = middleware.XSRF(c.Security.XSRF == "on")(h)
	h = middleware.RequestID(h)
	h = middleware.CORS(c.CORS.AllowedOrigins)(h)
	if c.TLS.Enabled && c.TLS.HSTS {
		h = middleware.HSTS(h)
	}
	h = middleware.SecurityHeaders(h)
	h = middleware.Recover(h)
	return h
}

// metricsHandler assembles the chain for GET /metrics on the public listener.
// Metrics requests authenticate like any other, then are authorized: only the
// configured metrics principal (c.Security.MetricsUser) may read them. An empty
// MetricsUser, or auth being disabled, makes the endpoint return 403 (fail
// closed) since no request can present the metrics identity.
func metricsHandler(c *config.Config, chain *auth.Chain, theCache cache.Cache, trustedProxies []*net.IPNet) http.Handler {
	var h http.Handler = http.HandlerFunc(MetricsEndpoint)
	h = requireAppUser(c.Security.MetricsUser)(h)
	if chain != nil {
		h = chain.Middleware(h)
	}
	h = middleware.BruteForceLockout(theCache, c.Limits.MaxAuthFailuresPerMin, trustedProxies)(h)
	h = middleware.RateLimitPerIP(theCache, c.Limits.MaxRequestsPerMinIP, trustedProxies)(h)
	h = middleware.GlobalInflight(c.Limits.MaxConcurrentGlobal)(h)
	h = middleware.RequestID(h)
	if c.TLS.Enabled && c.TLS.HSTS {
		h = middleware.HSTS(h)
	}
	h = middleware.SecurityHeaders(h)
	h = middleware.Recover(h)
	return h
}

// forbiddenBody is the generic 403 body for authorization failures.
const forbiddenBody = `{"type":"Error","message":"forbidden"}`

func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(forbiddenBody))
}

// denyAppUser returns middleware that rejects (403) a request whose
// authenticated principal has AppUser == name. Used to keep the metrics-only
// principal off /pathql. An empty name disables the check.
func denyAppUser(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if name == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, ok := auth.FromContext(r.Context()); ok && p != nil && p.AppUser == name {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireAppUser returns middleware that rejects (403) any request whose
// authenticated principal is not AppUser == name. Gates /metrics to the metrics
// principal. An empty name forbids every request (fail closed).
func requireAppUser(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if name == "" {
				writeForbidden(w)
				return
			}
			p, ok := auth.FromContext(r.Context())
			if !ok || p == nil || p.AppUser != name {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	const configPath = "config.ini"

	var err error
	cfg, err = config.Load(configPath)
	if err != nil {
		log.Fatal(err)
	}

	// Warn if the config file is group- or world-readable: it may contain (or
	// reference) secrets, so it should be chmod 600.
	if info, statErr := os.Stat(configPath); statErr == nil {
		if info.Mode().Perm()&0o077 != 0 {
			log.Printf("WARNING: %s is group/other-accessible (mode %04o); it may contain secrets - run: chmod 600 %s",
				configPath, info.Mode().Perm(), configPath)
		}
	}

	// The abuse-protection / JWKS cache. Shared by the rate limiter and the JWT
	// authenticator; closed on shutdown.
	sharedCache, err = cache.NewEmbedded(cfg.Cache.MemoryMB)
	if err != nil {
		log.Fatalf("cache: %v", err)
	}
	defer sharedCache.Close()

	trustedProxies, err := middleware.ParseTrustedProxies(cfg.Security.TrustedProxies)
	if err != nil {
		log.Fatal(err)
	}

	// Optional IP firewall: allow/deny CIDR lists gating every route. Parsed once
	// here; the config validated the entries, so parsing cannot fail.
	firewallAllow, err := middleware.ParseTrustedProxies(cfg.Security.AllowIPs)
	if err != nil {
		log.Fatal(err)
	}
	firewallDeny, err := middleware.ParseTrustedProxies(cfg.Security.DenyIPs)
	if err != nil {
		log.Fatal(err)
	}

	// Open the database connections. With identity_kind "none" a single shared
	// pool (the top-level dsn) serves every request and there is no RLS isolation.
	// With "login_role", rolePools serves caller queries on per-role connections
	// and `pool` is the baseline connection (authenticated as roles.baseline_role)
	// used for auth lookups, admin CRUD and catalog reads.
	baseDSN := cfg.DSN
	if cfg.Security.IdentityKind == "login_role" {
		pw := rolePasswordFunc()
		defaults := db.PoolParams{
			MaxOpen:         cfg.Database.MaxOpenConns,
			MaxIdle:         cfg.Database.MaxIdleConns,
			ConnMaxLifetime: time.Duration(cfg.Database.ConnMaxLifetimeMs) * time.Millisecond,
			ConnMaxIdleTime: time.Duration(cfg.Database.ConnMaxIdleTimeMs) * time.Millisecond,
		}
		rolePools, err = db.NewRolePools(cfg.Driver, cfg.Roles.BaseDSN, cfg.Database.MaxTotalBackends, cfg.Roles.WarmPoolLimit, defaults)
		if err != nil {
			log.Fatal(err)
		}
		rolePools.UseRolePassword(pw)
		defer rolePools.Close()
		baseDSN = cfg.Roles.BaseDSN + " user=" + cfg.Roles.BaselineRole +
			" password=" + pw(cfg.Roles.BaselineRole)
		log.Printf("identity model: login_role (per-role connections, current_user RLS)")
	} else {
		log.Printf("identity model: none (single shared connection, no row-level security)")
	}
	pool, err = db.OpenPool(
		cfg.Driver,
		baseDSN,
		cfg.Database.MaxOpenConns,
		cfg.Database.MaxIdleConns,
		time.Duration(cfg.Database.ConnMaxLifetimeMs)*time.Millisecond,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close(pool)

	// Admin-side user CRUD over the auth tables (gated to admin_user on /admin/*).
	userAdmin, err = auth.NewUserAdmin(pool.DB, cfg.Security.AuthTablePrefix)
	if err != nil {
		log.Fatal(err)
	}

	// Lazy startup: warn but keep going if the database is unreachable now.
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	if err := db.Ping(pingCtx, pool); err != nil {
		log.Printf("WARNING: database not reachable at startup: %v (continuing; will retry on demand)", err)
	}
	cancelPing()

	// Verify the connected role's posture (not superuser, no write access, no
	// dangerous functions, RLS on readable tables) before serving traffic.
	runStartupChecks(cfg, pool)

	chain, err := buildAuthChain(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if chain == nil {
		log.Printf("WARNING: authentication is DISABLED (no auth.methods configured); anyone who can reach %s may run SQL", cfg.Listen)
	}
	if cfg.WritesEnabled() && cfg.Security.IdentityKind == "none" {
		log.Printf("WARNING: writes are ENABLED with identity_kind=none; every caller writes as the same database role with no per-caller row-level authorization (single-tenant only) - use identity_kind=login_role with RLS WITH CHECK policies for multi-tenant writes")
	}

	// One router on the public listener (net/http ServeMux with method patterns,
	// Go 1.22+). OPTIONS is registered so a CORS preflight reaches the chain (the
	// CORS middleware answers it with 204). /metrics is served here too but gated
	// inside metricsHandler to the metrics principal, since top_queries leaks
	// query text and must never be world-readable.
	pathqlH := publicHandler(cfg, chain, sharedCache, trustedProxies)
	router := http.NewServeMux()
	router.Handle("POST /pathql", pathqlH)
	router.Handle("OPTIONS /pathql", pathqlH)
	router.Handle("GET /health", healthHandler(newHealthChecker(pool)))
	schemaH := schemaHandler(cfg, chain, sharedCache, trustedProxies)
	router.Handle("GET /schema", schemaH)
	router.Handle("OPTIONS /schema", schemaH)
	router.Handle("GET /metrics", metricsHandler(cfg, chain, sharedCache, trustedProxies))
	router.Handle("POST /admin/users", adminHandler(cfg, chain, sharedCache, trustedProxies, adminAddUser))
	router.Handle("DELETE /admin/users/{id}", adminHandler(cfg, chain, sharedCache, trustedProxies, adminDeleteUser))
	router.Handle("GET /admin/roles/sync", adminHandler(cfg, chain, sharedCache, trustedProxies, adminRolesSync))

	readTimeout := time.Duration(cfg.Timeouts.ReadMs) * time.Millisecond
	writeTimeout := time.Duration(cfg.Timeouts.WriteMs) * time.Millisecond
	idleTimeout := time.Duration(cfg.Timeouts.IdleMs) * time.Millisecond

	// The IP firewall wraps the whole router so it gates every route uniformly
	// (a no-op passthrough when no allow/deny lists are configured).
	rootHandler := middleware.Firewall(firewallAllow, firewallDeny, trustedProxies)(router)

	publicSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      rootHandler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Optional plain-HTTP redirect server that 301s everything to https. Only
	// built when TLS is enabled and a redirect address is configured.
	var redirectSrv *http.Server
	if cfg.TLS.Enabled && cfg.TLS.RedirectHTTP != "" {
		redirectSrv = &http.Server{
			Addr:         cfg.TLS.RedirectHTTP,
			Handler:      http.HandlerFunc(redirectToHTTPS),
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 2)
	go func() {
		if cfg.TLS.Enabled {
			log.Printf("public listener on %s (HTTPS, POST /pathql, GET /metrics)", cfg.Listen)
			if err := publicSrv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serveErr <- err
			}
			return
		}
		log.Printf("public listener on %s (POST /pathql, GET /metrics)", cfg.Listen)
		if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()
	if redirectSrv != nil {
		go func() {
			log.Printf("http->https redirect listener on %s", cfg.TLS.RedirectHTTP)
			if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serveErr <- err
			}
		}()
	}

	// Wait for a shutdown signal or a fatal serve error.
	select {
	case <-ctx.Done():
		log.Print("shutdown signal received, draining...")
	case err := <-serveErr:
		log.Printf("listener error: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := publicSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("public server shutdown: %v", err)
	}
	if redirectSrv != nil {
		if err := redirectSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("redirect server shutdown: %v", err)
		}
	}
}

// runStartupChecks runs the startup hardening self-check according to
// cfg.Security.StartupChecks: "off" skips it, "warn" logs any findings, and
// "enforce" additionally aborts startup on a critical finding (superuser role,
// write privileges, or a weak login_role password secret). It combines a
// config-only check (the role password secret) with the database catalog check,
// so the secret check still runs when the database is unreachable. Findings are
// advisory in warn mode so a developer setup without full hardening still runs.
func runStartupChecks(c *config.Config, pool *pathsqlx.DB) {
	if c.Security.StartupChecks == "off" {
		return
	}
	var warnings, critical []string

	// Config-only check: a weak login_role password secret. It needs no database
	// connection, so it runs even when the catalog check below cannot.
	if finding, weak := c.WeakRoleSecretFinding(); weak {
		critical = append(critical, finding)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dbChecked := true
	// A readable table without RLS is a silent full-table exposure only where RLS
	// is the boundary, so escalate it to critical (aborting under enforce) just
	// for login_role; in "none" mode the shared role intentionally sees all rows.
	noRLSIsCritical := c.Security.StartupChecks == "enforce" && c.Security.IdentityKind == "login_role"
	// With writes enabled and RLS the boundary under enforce, a writable table
	// without a WITH CHECK policy is a silent cross-tenant write path: critical.
	writeRLSIsCritical := c.Security.StartupChecks == "enforce" && c.Security.IdentityKind == "login_role"
	rep, err := db.VerifyHardening(ctx, pool, c.Driver, c.Security.AuthTablePrefix, noRLSIsCritical, c.WritesEnabled(), writeRLSIsCritical)
	if err != nil {
		log.Printf("WARNING: startup hardening check could not run: %v", err)
		dbChecked = false
	} else {
		warnings = append(warnings, rep.Warnings...)
		critical = append(critical, rep.Critical...)
	}

	for _, w := range warnings {
		log.Printf("WARNING: hardening: %s", w)
	}
	for _, cr := range critical {
		log.Printf("CRITICAL: hardening: %s", cr)
	}
	if c.Security.StartupChecks == "enforce" && len(critical) > 0 {
		log.Fatalf("startup_checks=enforce: %d critical hardening finding(s); aborting startup", len(critical))
	}
	if dbChecked && len(warnings) == 0 && len(critical) == 0 {
		log.Printf("hardening: startup checks passed")
	}
}

// redirectToHTTPS responds to any plain-HTTP request with a 301 to the same host
// and path over https, used by the optional TLS redirect listener.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	target := "https://" + host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
