package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mevdschee/pathsqlx"

	"github.com/mevdschee/pathql-go/internal/auth"
	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
)

// setTestConfig installs a minimal valid *config.Config into the package-level
// cfg for the duration of the test. PathQlEndpoint now reads cfg (RLS options,
// timeout, multi-statement policy), so handler tests must provide one.
func setTestConfig(t *testing.T) {
	t.Helper()
	old := cfg
	cfg = &config.Config{}
	cfg.Security.SessionVariable = "app.user"
	cfg.Security.ReadOnly = true
	cfg.Security.BlockMultipleStatements = true
	cfg.Limits.MaxQueryMs = 5000
	cfg.Limits.MaxBodyBytes = 1048576
	t.Cleanup(func() { cfg = old })
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

// TestPathQlEndpointGenericErrorOnDBFailure verifies that when the query runs
// against an unreachable pool, the client gets a generic 500 body that does NOT
// contain raw driver text.
func TestPathQlEndpointGenericErrorOnDBFailure(t *testing.T) {
	setTestConfig(t)
	setUnreachablePool(t)

	req := httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1"}`))
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

// TestPathQlEndpointBlocksMultipleStatements verifies that, with the policy on,
// a stacked query is rejected with a generic 400 before it ever reaches the
// database (the pool is left unreachable to prove it is never queried).
func TestPathQlEndpointBlocksMultipleStatements(t *testing.T) {
	setTestConfig(t)
	setUnreachablePool(t)

	req := httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1; DROP TABLE users"}`))
	rw := httptest.NewRecorder()

	PathQlEndpoint(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body %q)", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	if !strings.Contains(body, "single statement") {
		t.Errorf("expected single-statement message, got %q", body)
	}
}

// TestPathQlEndpointAllowsTrailingSemicolon verifies a single trailing semicolon
// is NOT treated as multiple statements (it reaches the DB and fails there with
// a generic 500 against the unreachable pool).
func TestPathQlEndpointAllowsTrailingSemicolon(t *testing.T) {
	setTestConfig(t)
	setUnreachablePool(t)

	req := httptest.NewRequest(http.MethodPost, "/pathql",
		strings.NewReader(`{"query":"SELECT 1;"}`))
	rw := httptest.NewRecorder()

	PathQlEndpoint(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 (reaches unreachable DB), got %d (body %q)", rw.Code, rw.Body.String())
	}
}

// TestHasMultipleStatements covers the conservative stacked-query detector.
func TestHasMultipleStatements(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want bool
	}{
		{"single", "SELECT 1", false},
		{"single trailing semicolon", "SELECT 1;", false},
		{"single trailing semicolon and spaces", "SELECT 1;   \n  ", false},
		{"trailing semicolon then line comment", "SELECT 1; -- done", false},
		{"trailing semicolon then block comment", "SELECT 1; /* done */", false},
		{"two statements", "SELECT 1; SELECT 2", true},
		{"two statements both terminated", "SELECT 1; SELECT 2;", true},
		{"double semicolon empty statement", "SELECT 1;;", true},
		{"injection", "SELECT 1; DROP TABLE users", true},
		{"semicolon inside single quotes", "SELECT 'a; b'", false},
		{"semicolon inside double-quoted identifier", `SELECT "co;l" FROM t`, false},
		{"semicolon inside line comment", "SELECT 1 -- a; b\n", false},
		{"semicolon inside block comment", "SELECT 1 /* a; b */", false},
		{"escaped quote then real separator", "SELECT 'it''s'; SELECT 2", true},
		{"dollar quoted body with semicolon", "SELECT $$a; b$$", false},
		{"tagged dollar quote with semicolon", "SELECT $tag$a; b$tag$", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasMultipleStatements(c.sql); got != c.want {
				t.Errorf("hasMultipleStatements(%q) = %v, want %v", c.sql, got, c.want)
			}
		})
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
	// (nil) so requests reach the handler without credentials; the handler will
	// hit the unreachable pool, but the rate limiter sits before it so the first
	// requests just return 500 and the over-limit one returns 429.
	lc := *cfg
	lc.Limits.MaxRequestsPerMinIP = 2
	lc.Limits.MaxConcurrentGlobal = 100
	lc.Limits.MaxConcurrentPerUser = 100
	setUnreachablePool(t)

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

	// First two are allowed (reach the handler -> 500 from unreachable pool).
	if code := send(); code != http.StatusInternalServerError {
		t.Fatalf("request 1: expected 500, got %d", code)
	}
	if code := send(); code != http.StatusInternalServerError {
		t.Fatalf("request 2: expected 500, got %d", code)
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
