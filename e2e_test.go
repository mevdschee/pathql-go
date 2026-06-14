//go:build e2e

// End-to-end tests that drive the real HTTP stack (the same publicHandler /
// buildAuthChain / MetricsEndpoint wiring main() uses) against a live
// PostgreSQL. They seed the pathql_auth_ tables and an RLS-protected demo table,
// then make real requests with real credentials and assert authentication,
// row-level security, read-only enforcement, multi-statement blocking, rate
// limiting, and JWT auth all behave correctly together.
//
// Build-tagged "e2e" so the default `go test ./...` stays hermetic. Run with:
//
//	go test -tags e2e -run TestE2E ./...
//
// DSN comes from PATHQL_E2E_DSN, defaulting to the same local dev database the
// pathsqlx tests use. The whole suite skips cleanly if the database is
// unreachable.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/mevdschee/pathsqlx"
	"golang.org/x/crypto/bcrypt"

	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
	"github.com/mevdschee/pathql-go/internal/db"
)

const (
	e2eDriver      = "postgres"
	e2eDefaultDSN  = "host=localhost port=5432 user=pathql password=pathql dbname=pathql sslmode=disable"
	e2eAlicePass   = "alice-secret-pw"
	e2eJWTSecret   = "e2e-hs256-shared-secret"
	e2eAPIKeyAlice = "alicekey0_3f8a1c4d9e2b6f70deadbeefcafef00d" // first 8 chars are the prefix
)

func e2eDSN() string {
	if v := os.Getenv("PATHQL_E2E_DSN"); v != "" {
		return v
	}
	return e2eDefaultDSN
}

// e2eEnv holds everything a subtest needs to talk to the running stack.
type e2eEnv struct {
	prefix    string // auth table prefix, e.g. "e2e_12345_"
	docsTable string // RLS demo table, e.g. "e2e_12345_docs"
	cache     cache.Cache
	pool      *pathsqlx.DB
}

// setupE2E connects to Postgres (skipping the whole suite if unreachable),
// installs a fresh isolated schema with seeded users / api keys / RLS rows, sets
// the package globals the handlers read, and registers cleanup that drops the
// tables and restores the globals.
func setupE2E(t *testing.T) *e2eEnv {
	t.Helper()

	p, err := db.OpenPool(e2eDriver, e2eDSN(), 10, 5, 5*time.Minute)
	if err != nil {
		t.Skipf("cannot open pool (driver/dsn): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := db.Ping(ctx, p); err != nil {
		_ = db.Close(p)
		t.Skipf("PostgreSQL not reachable at %q: %v", e2eDSN(), err)
	}

	prefix := fmt.Sprintf("e2e_%d_", os.Getpid())
	usersTable := prefix + "users"
	keysTable := prefix + "api_keys"
	docsTable := prefix + "docs"

	sqlDB := p.DB // embedded *sqlx.DB

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(context.Background(), q, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, q)
		}
	}

	// Clean any leftovers from a previous aborted run, then build the schema.
	drop := func() {
		_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+docsTable)
		_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+keysTable)
		_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+usersTable)
	}
	drop()

	exec(fmt.Sprintf(`CREATE TABLE %s (
		id            bigserial PRIMARY KEY,
		username      text NOT NULL UNIQUE,
		password_hash text,
		app_user      text NOT NULL,
		enabled       boolean NOT NULL DEFAULT true,
		created_at    timestamptz NOT NULL DEFAULT now()
	)`, usersTable))

	exec(fmt.Sprintf(`CREATE TABLE %s (
		id           bigserial PRIMARY KEY,
		user_id      bigint NOT NULL REFERENCES %s(id),
		key_prefix   text NOT NULL,
		key_hash     bytea NOT NULL,
		name         text,
		expires_at   timestamptz,
		enabled      boolean NOT NULL DEFAULT true,
		last_used_at timestamptz,
		UNIQUE (key_prefix)
	)`, keysTable, usersTable))

	// RLS demo table. pathql connects as a non-superuser, non-bypassrls role, and
	// FORCE ROW LEVEL SECURITY makes the policy apply even to the table owner.
	exec(fmt.Sprintf(`CREATE TABLE %s (
		id     bigint PRIMARY KEY,
		tenant text NOT NULL,
		body   text NOT NULL
	)`, docsTable))
	// Seed the RLS rows BEFORE enabling row-level security, otherwise the owner's
	// own INSERT is denied because no app.user is set during setup.
	exec(fmt.Sprintf(`INSERT INTO %s (id, tenant, body) VALUES
		(1,'alice','alice-doc-one'),
		(2,'alice','alice-doc-two'),
		(3,'bob','bob-doc-one')`, docsTable))
	exec(fmt.Sprintf(`ALTER TABLE %s ENABLE ROW LEVEL SECURITY`, docsTable))
	exec(fmt.Sprintf(`ALTER TABLE %s FORCE ROW LEVEL SECURITY`, docsTable))
	exec(fmt.Sprintf(`CREATE POLICY %s_isolation ON %s
		USING (tenant = current_setting('app.user', true))`, docsTable, docsTable))

	// Seed two principals: alice (password + API key) and bob (password only).
	aliceHash, err := bcrypt.GenerateFromPassword([]byte(e2eAlicePass), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	exec(fmt.Sprintf(`INSERT INTO %s (username, password_hash, app_user, enabled)
		VALUES ($1,$2,$3,true)`, usersTable), "alice", string(aliceHash), "alice")
	bobHash, _ := bcrypt.GenerateFromPassword([]byte("bob-secret-pw"), bcrypt.DefaultCost)
	exec(fmt.Sprintf(`INSERT INTO %s (username, password_hash, app_user, enabled)
		VALUES ($1,$2,$3,true)`, usersTable), "bob", string(bobHash), "bob")

	// API key for alice: store the sha-256 of the full key + its 8-char prefix.
	sum := sha256.Sum256([]byte(e2eAPIKeyAlice))
	exec(fmt.Sprintf(`INSERT INTO %s (user_id, key_prefix, key_hash, name, enabled)
		SELECT id, $1, $2, 'e2e', true FROM %s WHERE username='alice'`, keysTable, usersTable),
		e2eAPIKeyAlice[:8], sum[:])

	// Install the package globals the handlers read.
	c, err := cache.NewEmbedded(16)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}

	oldCfg, oldPool, oldCache := cfg, pool, sharedCache
	cfg = baseE2EConfig(prefix)
	pool = p
	sharedCache = c

	t.Cleanup(func() {
		drop()
		_ = db.Close(p)
		_ = c.Close()
		cfg = oldCfg
		pool = oldPool
		sharedCache = oldCache
	})

	return &e2eEnv{prefix: prefix, docsTable: docsTable, cache: c, pool: p}
}

// baseE2EConfig is a fully-populated config for the running stack with auth on
// (apikey + basic), RLS via the dotted session variable, and read-only on.
func baseE2EConfig(prefix string) *config.Config {
	c := &config.Config{Driver: e2eDriver, DSN: e2eDSN()}
	c.Security.AuthTablePrefix = prefix
	c.Security.SessionVariable = "app.user"
	c.Security.ReadOnly = true
	c.Security.BlockMultipleStatements = true
	c.Auth.Methods = []string{"apikey", "basic"}
	c.Auth.APIKeyHeader = "X-API-Key"
	c.Limits.MaxQueryMs = 5000
	c.Limits.MaxBodyBytes = 1 << 20
	c.Limits.MaxConcurrentPerUser = 50
	c.Limits.MaxConcurrentGlobal = 200
	c.Limits.MaxRequestsPerMinIP = 1000
	c.Cache.MemoryMB = 16
	c.Cache.JWKSTTLDuration = time.Hour
	return c
}

// serveE2E builds the real public handler from the current globals and wraps it
// in an httptest server.
func serveE2E(t *testing.T) *httptest.Server {
	t.Helper()
	chain, err := buildAuthChain(cfg)
	if err != nil {
		t.Fatalf("buildAuthChain: %v", err)
	}
	return httptest.NewServer(publicHandler(cfg, chain, sharedCache, nil))
}

type e2eResp struct {
	status int
	body   string
}

func post(t *testing.T, srv *httptest.Server, query string, hdr map[string]string) e2eResp {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/pathql", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:6000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return e2eResp{status: resp.StatusCode, body: string(b)}
}

func TestE2EAuthAndRLS(t *testing.T) {
	env := setupE2E(t)
	srv := serveE2E(t)
	defer srv.Close()

	docs := env.docsTable
	q := "SELECT id, tenant, body FROM " + docs + " ORDER BY id"

	t.Run("no credentials -> 401", func(t *testing.T) {
		r := post(t, srv, q, nil)
		if r.status != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "unauthorized") {
			t.Errorf("expected generic unauthorized, got %s", r.body)
		}
	})

	t.Run("api key -> only alice rows (RLS)", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{"X-API-Key": e2eAPIKeyAlice})
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "alice-doc-one") || !strings.Contains(r.body, "alice-doc-two") {
			t.Errorf("expected alice docs, got %s", r.body)
		}
		if strings.Contains(r.body, "bob-doc-one") {
			t.Errorf("RLS leak: bob's row visible to alice: %s", r.body)
		}
	})

	t.Run("basic auth alice -> only alice rows", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{
			"Authorization": basicAuth("alice", e2eAlicePass),
		})
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "alice-doc-one") {
			t.Errorf("expected alice docs, got %s", r.body)
		}
		if strings.Contains(r.body, "bob-doc-one") {
			t.Errorf("RLS leak for basic auth: %s", r.body)
		}
	})

	t.Run("basic auth wrong password -> 401", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{
			"Authorization": basicAuth("alice", "wrong"),
		})
		if r.status != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
	})

	t.Run("basic auth bob -> only bob row (per-principal isolation)", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{
			"Authorization": basicAuth("bob", "bob-secret-pw"),
		})
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "bob-doc-one") {
			t.Errorf("expected bob doc, got %s", r.body)
		}
		if strings.Contains(r.body, "alice-doc") {
			t.Errorf("RLS leak: alice rows visible to bob: %s", r.body)
		}
	})

	t.Run("multi-statement -> 400", func(t *testing.T) {
		r := post(t, srv, "SELECT 1; DROP TABLE "+docs, map[string]string{"X-API-Key": e2eAPIKeyAlice})
		if r.status != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "single statement") {
			t.Errorf("expected single-statement message, got %s", r.body)
		}
	})

	t.Run("read-only tx blocks writes", func(t *testing.T) {
		ins := fmt.Sprintf("INSERT INTO %s (id, tenant, body) VALUES (999, 'alice', 'should-not-persist') RETURNING id", docs)
		r := post(t, srv, ins, map[string]string{"X-API-Key": e2eAPIKeyAlice})
		if r.status == http.StatusOK {
			t.Fatalf("write unexpectedly succeeded in a read-only tx: %s", r.body)
		}
		// Verify, out of band as the table owner, that nothing was written.
		var n int
		if err := env.pool.DB.GetContext(context.Background(), &n,
			"SELECT count(*) FROM "+docs+" WHERE id = 999"); err != nil {
			t.Fatalf("verify count: %v", err)
		}
		if n != 0 {
			t.Fatalf("read-only enforcement failed: row 999 was inserted")
		}
	})
}

func TestE2EJWTAuthWithRLS(t *testing.T) {
	env := setupE2E(t)

	// Reconfigure auth to JWT (HS256), requiring a matching enabled user row, then
	// build the chain.
	cfg.Auth.Methods = []string{"jwt"}
	cfg.Auth.JWTAlgorithms = []string{"HS256"}
	cfg.Auth.JWTHS256Secret = e2eJWTSecret
	cfg.Auth.JWTUserClaim = "sub"
	cfg.Auth.RequireUserRow = true

	srv := serveE2E(t)
	defer srv.Close()

	q := "SELECT id, tenant, body FROM " + env.docsTable + " ORDER BY id"

	sign := func(sub string, exp time.Time) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": sub,
			"exp": exp.Unix(),
			"iat": time.Now().Add(-time.Minute).Unix(),
		})
		s, err := tok.SignedString([]byte(e2eJWTSecret))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	t.Run("valid HS256 token (sub=alice) -> alice rows under RLS", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{
			"Authorization": "Bearer " + sign("alice", time.Now().Add(time.Hour)),
		})
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "alice-doc-one") || strings.Contains(r.body, "bob-doc-one") {
			t.Errorf("expected alice-only rows, got %s", r.body)
		}
	})

	t.Run("expired token -> 401", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{
			"Authorization": "Bearer " + sign("alice", time.Now().Add(-time.Hour)),
		})
		if r.status != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
	})

	t.Run("token signed with wrong secret -> 401", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "alice", "exp": time.Now().Add(time.Hour).Unix(),
		})
		bad, _ := tok.SignedString([]byte("not-the-secret"))
		r := post(t, srv, q, map[string]string{"Authorization": "Bearer " + bad})
		if r.status != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
	})

	t.Run("unknown subject (no user row) -> 401", func(t *testing.T) {
		r := post(t, srv, q, map[string]string{
			"Authorization": "Bearer " + sign("carol", time.Now().Add(time.Hour)),
		})
		if r.status != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
	})
}

func TestE2ERateLimitAndMetrics(t *testing.T) {
	env := setupE2E(t)

	// Tight per-IP budget so we can trip it, and rebuild the handler with it.
	cfg.Limits.MaxRequestsPerMinIP = 3
	srv := serveE2E(t)
	defer srv.Close()

	q := "SELECT id, tenant, body FROM " + env.docsTable

	var got429 bool
	for i := 0; i < 6; i++ {
		r := post(t, srv, q, map[string]string{"X-API-Key": e2eAPIKeyAlice})
		if r.status == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("expected a 429 after exceeding the per-IP budget")
	}

	// Metrics endpoint reports auth successes accumulated above.
	mrec := httptest.NewRecorder()
	mreq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	MetricsEndpoint(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("metrics status=%d", mrec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(mrec.Body.Bytes(), &m); err != nil {
		t.Fatalf("metrics not JSON: %v", err)
	}
	if _, ok := m["auth"]; !ok {
		t.Errorf("metrics missing auth counters: %s", mrec.Body.String())
	}
}

// basicAuth builds an HTTP Basic Authorization header value.
func basicAuth(user, pass string) string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}
