package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mevdschee/pathsqlx"

	"github.com/mevdschee/pathql-go/internal/auth"
	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
	"github.com/mevdschee/pathql-go/internal/db"
)

// setTestConfig installs a minimal valid *config.Config into the package-level
// cfg for the duration of the test. PathQlEndpoint now reads cfg (RLS options,
// timeout, role prefix), so handler tests must provide one.
func setTestConfig(t *testing.T) {
	t.Helper()
	old := cfg
	cfg = &config.Config{}
	cfg.Security.ReadOnly = true
	cfg.Security.IdentityKind = "login_role"
	cfg.Roles.Prefix = "pathql_r_"
	cfg.Limits.MaxQueryMs = 5000
	cfg.Limits.MaxBodyBytes = 1048576
	t.Cleanup(func() { cfg = old })
}

// withPrincipal returns a copy of req carrying an authenticated principal, as the
// auth middleware would set after a successful login.
func withPrincipal(req *http.Request, appUser string, userID int64) *http.Request {
	return req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{AppUser: appUser, UserID: userID}))
}

// errUnreachable is the canonical "driver could not connect" error. Its text is
// what the generic-error test asserts never reaches the client.
var errUnreachable = errors.New("pq: dial tcp 127.0.0.1:5432: connect: connection refused")

// unreachableDriver is a minimal database/sql driver whose Open always fails,
// simulating a database that cannot be reached. sqlx.Open is lazy, so the
// failure surfaces only when a query actually needs a connection, which is the
// path PathQlEndpoint exercises.
type unreachableDriver struct{}

func (unreachableDriver) Open(name string) (driver.Conn, error) { return nil, errUnreachable }

const unreachableDriverName = "pathqltestunreachable"

func init() {
	sql.Register(unreachableDriverName, unreachableDriver{})
}

// setUnreachablePool points the package-level shared pool at the unreachable
// driver so handler tests can exercise the DB-error path without a live
// database, offline and deterministic.
func setUnreachablePool(t *testing.T) {
	t.Helper()
	p, err := pathsqlx.Open(unreachableDriverName, "")
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	old := pool
	pool = p
	t.Cleanup(func() {
		_ = p.DB.DB.Close()
		pool = old
	})
}

// setUnreachableRolePools points the package-level rolePools manager at the
// unreachable driver. pathsqlx.Open is lazy, so Acquire succeeds and the failure
// surfaces only when RunQuery dials a connection, exercising the DB-error path a
// caller query takes in the per-role model.
func setUnreachableRolePools(t *testing.T) {
	t.Helper()
	rp, err := db.NewRolePoolsWithOpener(unreachableDriverName, "host=unreachable", 10, 4,
		db.PoolParams{MaxOpen: 4, MaxIdle: 2}, pathsqlx.Open)
	if err != nil {
		t.Fatalf("role pools: %v", err)
	}
	old := rolePools
	rolePools = rp
	t.Cleanup(func() {
		_ = rp.Close()
		rolePools = old
	})
}

// TestPathQlEndpointMalformedJSON verifies a malformed body yields a clean 400
// (not a panic) with a generic JSON error.
func TestPathQlEndpointMalformedJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/pathql", strings.NewReader("{not json"))
	rw := httptest.NewRecorder()

	PathQlEndpoint(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, `"type":"Error"`) {
		t.Errorf("expected generic Error body, got %q", body)
	}
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("expected generic message, got %q", body)
	}
}

// TestPathQlEndpointArrayParams verifies array params are rejected with a 400
// and a clean message.
func TestPathQlEndpointArrayParams(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1","params":[1,2,3]}`))
	rw := httptest.NewRecorder()

	PathQlEndpoint(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "params must be an object") {
		t.Errorf("unexpected body: %q", rw.Body.String())
	}
}

// TestPathQlEndpointSQLGate verifies the optional SQL gate rejects a
// system-catalog query with a clean 400 before any database work, and that with
// the gate off the same query is not rejected by the gate.
func TestPathQlEndpointSQLGate(t *testing.T) {
	setTestConfig(t)
	const body = `{"query":"SELECT * FROM pg_catalog.pg_authid"}`

	// Gate on: rejected at the edge. No principal or pool is needed because the
	// gate runs before identity resolution and any database access.
	cfg.Security.SQLGate = "on"
	rw := httptest.NewRecorder()
	PathQlEndpoint(rw, httptest.NewRequest(http.MethodPost, "/pathql", strings.NewReader(body)))
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("gate on: expected 400, got %d (body %q)", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "system catalogs") {
		t.Errorf("gate on: unexpected body: %q", rw.Body.String())
	}

	// Gate off: the gate does not reject. With login_role and no principal the
	// request then fails identity resolution (401), proving the 400 above came
	// from the gate and that the gate stays out of the way when off.
	cfg.Security.SQLGate = "off"
	rw = httptest.NewRecorder()
	PathQlEndpoint(rw, httptest.NewRequest(http.MethodPost, "/pathql", strings.NewReader(body)))
	if rw.Code == http.StatusBadRequest {
		t.Errorf("gate off: query was rejected (400 %q), want it to pass the gate", rw.Body.String())
	}
}

// TestPathQlEndpointGenericErrorOnDBFailure verifies that when the query runs
// against an unreachable pool, the client gets a generic 500 body that does NOT
// contain raw driver text.
func TestPathQlEndpointGenericErrorOnDBFailure(t *testing.T) {
	setTestConfig(t)
	setUnreachableRolePools(t)

	req := withPrincipal(httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1"}`)), "alice", 1)
	rw := httptest.NewRecorder()

	PathQlEndpoint(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body %q)", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	if !strings.Contains(body, "internal error") {
		t.Errorf("expected generic internal error, got %q", body)
	}
	// The generic body must not leak driver internals.
	for _, leak := range []string{"connection refused", "pq:", "dial tcp", "127.0.0.1", "sql:"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
			t.Errorf("response leaked driver detail %q: %q", leak, body)
		}
	}
}

// rejectingStore is a fake auth.UserStore that knows no users or keys, so every
// lookup misses and the chain ends up unauthorized.
type rejectingStore struct{}

func (rejectingStore) LookupAPIKeyByPrefix(ctx context.Context, prefix string) (*auth.APIKeyRecord, error) {
	return nil, auth.ErrNotFound
}

func (rejectingStore) LookupUserByUsername(ctx context.Context, username string) (*auth.UserRecord, error) {
	return nil, auth.ErrNotFound
}

func (rejectingStore) TouchAPIKey(ctx context.Context, userID int64, prefix string) error {
	return nil
}

// TestAuthMiddlewareRejects verifies the auth middleware returns 401 with the
// generic body when the chain rejects the credentials, and never reaches the
// handler.
func TestAuthMiddlewareRejects(t *testing.T) {
	store := rejectingStore{}
	chain := auth.NewChain(
		auth.NewAPIKeyAuthenticator(store, "X-API-Key"),
		auth.NewBasicAuthenticator(store),
	)

	reached := false
	guarded := chain.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1"}`))
	req.Header.Set("X-API-Key", "deadbeefcafef00d")
	rw := httptest.NewRecorder()

	guarded.ServeHTTP(rw, req)

	if reached {
		t.Fatal("handler should not be reached when auth fails")
	}
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, "unauthorized") {
		t.Errorf("expected generic unauthorized body, got %q", body)
	}
	if rw.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestMetricsEndpointTopUsers(t *testing.T) {
	topUsers.Record("u-metrics-test", 40)
	topUsers.Record("u-metrics-test", 60) // count 2, total 100

	rec := httptest.NewRecorder()
	MetricsEndpoint(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	var resp struct {
		TopUsers []UserStat `json:"top_users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	var got *UserStat
	for i := range resp.TopUsers {
		if resp.TopUsers[i].User == "u-metrics-test" {
			got = &resp.TopUsers[i]
		}
	}
	if got == nil {
		t.Fatalf("top_users missing u-metrics-test: %s", rec.Body.String())
	}
	if got.Count != 2 || got.TotalMs < 100 {
		t.Errorf("top_users entry = %+v, want count=2 total_ms>=100", *got)
	}
}

// TestPublicChainRateLimits builds the real public middleware chain (offline:
// fake auth store, embedded cache) and verifies the per-IP rate limiter returns
// 429 once the configured per-minute budget is exceeded. It also confirms the
// chain answers a CORS preflight OPTIONS with 204.
func TestPublicChainRateLimits(t *testing.T) {
	setTestConfig(t)

	c, err := cache.NewEmbedded(8)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	defer c.Close()

	// A tiny per-IP budget so we can trip it deterministically. No auth chain
	// (nil) so requests reach the handler without credentials; with no principal
	// the handler returns 401, but the rate limiter sits before it so the first
	// requests pass through and the over-limit one returns 429.
	lc := *cfg
	lc.Limits.MaxRequestsPerMinIP = 2
	lc.Limits.MaxConcurrentGlobal = 100
	lc.Limits.MaxConcurrentPerUser = 100

	h := publicHandler(&lc, nil, c, nil)

	send := func() int {
		req := httptest.NewRequest(http.MethodPost, "/pathql",
			strings.NewReader(`{"query":"SELECT 1"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.7:5000"
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		return rw.Code
	}

	// First two are allowed through the limiter (reach the handler -> 401, no
	// principal). The third exceeds the per-minute budget before the handler.
	if code := send(); code != http.StatusUnauthorized {
		t.Fatalf("request 1: expected 401, got %d", code)
	}
	if code := send(); code != http.StatusUnauthorized {
		t.Fatalf("request 2: expected 401, got %d", code)
	}
	// Third exceeds the per-minute budget.
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("request 3: expected 429, got %d", code)
	}

	// CORS preflight: an OPTIONS with an allowed origin is answered 204 by the
	// CORS middleware without reaching the handler.
	lc.CORS.AllowedOrigins = []string{"https://app.example"}
	hc := publicHandler(&lc, nil, c, nil)
	preflight := httptest.NewRequest(http.MethodOptions, "/pathql", nil)
	preflight.Header.Set("Origin", "https://app.example")
	preflight.RemoteAddr = "203.0.113.8:5000"
	prw := httptest.NewRecorder()
	hc.ServeHTTP(prw, preflight)
	if prw.Code != http.StatusNoContent {
		t.Fatalf("preflight: expected 204, got %d", prw.Code)
	}
	if prw.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("preflight: expected echoed origin, got %q", prw.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestPublicChainRequiresJSONContentType verifies the content-type guard rejects
// a non-JSON POST with 415 before it reaches the handler.
func TestPublicChainRequiresJSONContentType(t *testing.T) {
	setTestConfig(t)

	c, err := cache.NewEmbedded(8)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	defer c.Close()
	setUnreachablePool(t)

	h := publicHandler(cfg, nil, c, nil)
	req := httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1"}`))
	req.Header.Set("Content-Type", "text/plain")
	req.RemoteAddr = "203.0.113.9:5000"
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d (body %q)", rw.Code, rw.Body.String())
	}
}

// --- cost-ceiling handler integration -------------------------------------
//
// costPlanDriver is a minimal fake whose EXPLAIN returns a fixed, deliberately
// over-budget plan. It lets the cost-ceiling rejection be exercised through the
// real handler without a live planner.
type costPlanConn struct{}

func (costPlanConn) Prepare(q string) (driver.Stmt, error) { return costPlanStmt{q: q}, nil }
func (costPlanConn) Close() error                          { return nil }
func (costPlanConn) Begin() (driver.Tx, error)             { return costPlanTx{}, nil }
func (costPlanConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return costPlanTx{}, nil
}

type costPlanTx struct{}

func (costPlanTx) Commit() error   { return nil }
func (costPlanTx) Rollback() error { return nil }

type costPlanStmt struct{ q string }

func (costPlanStmt) Close() error                               { return nil }
func (costPlanStmt) NumInput() int                              { return -1 }
func (costPlanStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(0), nil }
func (s costPlanStmt) Query([]driver.Value) (driver.Rows, error) {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s.q)), "EXPLAIN") {
		return &costPlanRows{plan: []byte(`[{"Plan":{"Total Cost":1.0,"Plan Rows":1000000}}]`)}, nil
	}
	return &costPlanRows{}, nil
}

type costPlanRows struct {
	plan []byte
	done bool
}

func (r *costPlanRows) Columns() []string {
	if r.plan == nil {
		return []string{"x"}
	}
	return []string{"QUERY PLAN"}
}
func (r *costPlanRows) Close() error { return nil }
func (r *costPlanRows) Next(dest []driver.Value) error {
	if r.plan == nil || r.done {
		return io.EOF
	}
	dest[0] = r.plan
	r.done = true
	return nil
}

type costPlanDriver struct{}

func (costPlanDriver) Open(string) (driver.Conn, error) { return costPlanConn{}, nil }

const costPlanDriverName = "pathqltestcostplan"

func init() { sql.Register(costPlanDriverName, costPlanDriver{}) }

// TestPathQlEndpointCostCeilingRejects verifies that when the planner estimate
// exceeds the configured bound, the handler returns 400 with a generic message
// that does not leak the estimate or the limit.
func TestPathQlEndpointCostCeilingRejects(t *testing.T) {
	setTestConfig(t)
	cfg.Security.IdentityKind = "none" // shared pool, no principal needed
	cfg.Driver = "postgres"            // enables the EXPLAIN cost check
	cfg.Limits.MaxEstimatedRows = 100

	p, err := pathsqlx.Open(costPlanDriverName, "")
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	old := pool
	pool = p
	t.Cleanup(func() {
		_ = p.DB.DB.Close()
		pool = old
	})

	rw := httptest.NewRecorder()
	PathQlEndpoint(rw, httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1"}`)))

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body %q)", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	if !strings.Contains(body, "exceeds the configured limit") {
		t.Errorf("unexpected body: %q", body)
	}
	// The estimate and the limit must stay in the logs, not the client body.
	if strings.Contains(body, "1000000") || strings.Contains(body, "estimated rows") {
		t.Errorf("response leaked cost-estimate detail: %q", body)
	}
}
