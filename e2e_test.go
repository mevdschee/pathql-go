//go:build e2e

// End-to-end tests that drive the real HTTP stack (the same publicHandler /
// buildAuthChain / MetricsEndpoint wiring main() uses) against a live
// PostgreSQL. They seed the pathql_auth_ tables, per-user login roles and an
// RLS-protected demo table, then make real requests with real credentials and
// assert authentication, row-level security, read-only enforcement, rate
// limiting, and JWT auth all behave correctly together.
//
// Identity is the connected database role: each caller's query runs on a
// connection authenticated as its own login role (pathql_r_<id>), and the RLS
// policy compares owner = current_user, an unforgeable boundary.
//
// Build-tagged "e2e" so the default `go test ./...` stays hermetic. Run with:
//
//	go test -tags e2e -run TestE2E ./...
//
// DSN comes from PATHQL_E2E_DSN, defaulting to the same local dev database the
// pathsqlx tests use. The connecting user must be able to CREATE ROLE (superuser
// or CREATEROLE); the suite skips cleanly if the database is unreachable or roles
// cannot be managed.
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
	e2eRoleSecret  = "e2e-role-password-secret"
	e2eAPIKeyAlice = "alicekey0_3f8a1c4d9e2b6f70deadbeefcafef00d" // first 8 chars are the prefix
)

func e2eDSN() string {
	if v := os.Getenv("PATHQL_E2E_DSN"); v != "" {
		return v
	}
	return e2eDefaultDSN
}

// e2eBaseDSN is e2eDSN with any user= and password= tokens removed, the user-less
// base the per-role pools append "user=<role> password=<derived>" to.
func e2eBaseDSN() string {
	parts := strings.Fields(e2eDSN())
	out := parts[:0]
	for _, p := range parts {
		if strings.HasPrefix(p, "user=") || strings.HasPrefix(p, "password=") {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

// e2eEnv holds everything a subtest needs to talk to the running stack.
type e2eEnv struct {
	prefix    string // auth table prefix, e.g. "e2e_12345_"
	docsTable string // RLS demo table, e.g. "e2e_12345_docs"
	cache     cache.Cache
	pool      *pathsqlx.DB
}

// setupE2E connects to Postgres (skipping the whole suite if unreachable),
// installs a fresh isolated schema with seeded users / api keys / per-user login
// roles / RLS rows, sets the package globals the handlers read, and registers
// cleanup that drops the tables and roles and restores the globals.
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
	rolePrefix := fmt.Sprintf("e2e_%d_r_", os.Getpid())
	readerRole := fmt.Sprintf("e2e_%d_readers", os.Getpid())

	sqlDB := p.DB // embedded *sqlx.DB
	bg := context.Background()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(bg, q, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, q)
		}
	}

	// Clean any leftovers from a previous aborted run: the tables, then every role
	// in this run's namespace (the prefix plus the reader group). Best effort.
	drop := func() {
		_, _ = sqlDB.ExecContext(bg, "DROP TABLE IF EXISTS "+docsTable)
		_, _ = sqlDB.ExecContext(bg, "DROP TABLE IF EXISTS "+keysTable)
		_, _ = sqlDB.ExecContext(bg, "DROP TABLE IF EXISTS "+usersTable)
		_, _ = sqlDB.ExecContext(bg, fmt.Sprintf(
			`DO $$DECLARE r record; BEGIN
			   FOR r IN SELECT rolname FROM pg_roles
			            WHERE starts_with(rolname, '%s') OR rolname = '%s' LOOP
			     EXECUTE 'DROP OWNED BY ' || quote_ident(r.rolname);
			     EXECUTE 'DROP ROLE ' || quote_ident(r.rolname);
			   END LOOP;
			 END$$;`, rolePrefix, readerRole))
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

	// Seed two principals: alice (password + API key) and bob (password only),
	// capturing their ids so we can derive their login-role names.
	aliceHash, err := bcrypt.GenerateFromPassword([]byte(e2eAlicePass), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	bobHash, _ := bcrypt.GenerateFromPassword([]byte("bob-secret-pw"), bcrypt.DefaultCost)

	var aliceID, bobID int64
	if err := sqlDB.GetContext(bg, &aliceID, fmt.Sprintf(
		`INSERT INTO %s (username, password_hash, app_user, enabled) VALUES ($1,$2,$3,true) RETURNING id`,
		usersTable), "alice", string(aliceHash), "alice"); err != nil {
		t.Fatalf("insert alice: %v", err)
	}
	if err := sqlDB.GetContext(bg, &bobID, fmt.Sprintf(
		`INSERT INTO %s (username, password_hash, app_user, enabled) VALUES ($1,$2,$3,true) RETURNING id`,
		usersTable), "bob", string(bobHash), "bob"); err != nil {
		t.Fatalf("insert bob: %v", err)
	}

	// API key for alice: store the sha-256 of the full key + its 8-char prefix.
	sum := sha256.Sum256([]byte(e2eAPIKeyAlice))
	exec(fmt.Sprintf(`INSERT INTO %s (user_id, key_prefix, key_hash, name, enabled)
		SELECT id, $1, $2, 'e2e', true FROM %s WHERE username='alice'`, keysTable, usersTable),
		e2eAPIKeyAlice[:8], sum[:])

	aliceRole := fmt.Sprintf("%s%d", rolePrefix, aliceID)
	bobRole := fmt.Sprintf("%s%d", rolePrefix, bobID)
	rolePw := func(role string) string { return rolePassword(e2eRoleSecret, role) }

	// Create the reader group and the per-user login roles. Each role's password
	// is the same HMAC-derived value the server re-derives from e2eRoleSecret.
	// Managing roles needs CREATEROLE/superuser; skip cleanly if we lack it.
	execRoleOrSkip := func(q string) {
		if _, err := sqlDB.ExecContext(bg, q); err != nil {
			drop()
			_ = db.Close(p)
			t.Skipf("cannot manage login roles (need CREATEROLE or superuser): %v", err)
		}
	}
	execRoleOrSkip(fmt.Sprintf(`CREATE ROLE %s`, readerRole))
	for _, role := range []string{aliceRole, bobRole} {
		execRoleOrSkip(fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, role, rolePw(role)))
		execRoleOrSkip(fmt.Sprintf(`GRANT %s TO %s`, readerRole, role))
	}
	// Ensure the readers can reach the schema (PUBLIC usually already can).
	_, _ = sqlDB.ExecContext(bg, fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, readerRole))

	// RLS demo table. owner holds the managed role NAME, because the policy
	// compares owner = current_user and current_user is the connected login role.
	exec(fmt.Sprintf(`CREATE TABLE %s (
		id    bigint PRIMARY KEY,
		owner text NOT NULL,
		body  text NOT NULL
	)`, docsTable))
	exec(fmt.Sprintf(`INSERT INTO %s (id, owner, body) VALUES
		(1,'%s','alice-doc-one'),
		(2,'%s','alice-doc-two'),
		(3,'%s','bob-doc-one')`, docsTable, aliceRole, aliceRole, bobRole))
	exec(fmt.Sprintf(`ALTER TABLE %s ENABLE ROW LEVEL SECURITY`, docsTable))
	exec(fmt.Sprintf(`ALTER TABLE %s FORCE ROW LEVEL SECURITY`, docsTable))
	exec(fmt.Sprintf(`CREATE POLICY %s_isolation ON %s
		FOR SELECT TO %s USING (owner = current_user)`, docsTable, docsTable, readerRole))
	// Readers may SELECT; the RLS policy then filters to their own rows.
	exec(fmt.Sprintf(`GRANT SELECT ON %s TO %s`, docsTable, readerRole))

	// Install the package globals the handlers read.
	c, err := cache.NewEmbedded(16)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}

	defaults := db.PoolParams{MaxOpen: 5, MaxIdle: 2, ConnMaxLifetime: 5 * time.Minute, ConnMaxIdleTime: time.Minute}
	rp, err := db.NewRolePools(e2eDriver, e2eBaseDSN(), 50, 16, defaults)
	if err != nil {
		t.Fatalf("role pools: %v", err)
	}
	rp.UseRolePassword(rolePw)

	oldCfg, oldPool, oldRolePools, oldCache := cfg, pool, rolePools, sharedCache
	cfg = baseE2EConfig(prefix, rolePrefix, readerRole)
	pool = p
	rolePools = rp
	sharedCache = c

	t.Cleanup(func() {
		_ = rp.Close()
		drop()
		_ = db.Close(p)
		_ = c.Close()
		cfg = oldCfg
		pool = oldPool
		rolePools = oldRolePools
		sharedCache = oldCache
	})

	return &e2eEnv{prefix: prefix, docsTable: docsTable, cache: c, pool: p}
}

// baseE2EConfig is a fully-populated config for the running stack with auth on
// (apikey + basic), per-role connections (password auth), and read-only on.
func baseE2EConfig(prefix, rolePrefix, readerRole string) *config.Config {
	c := &config.Config{Driver: e2eDriver}
	c.Security.AuthTablePrefix = prefix
	c.Security.ReadOnly = true
	c.Auth.Methods = []string{"apikey", "basic"}
	c.Auth.APIKeyHeader = "X-API-Key"
	c.Roles.BaseDSN = e2eBaseDSN()
	c.Roles.PasswordSecret = e2eRoleSecret
	c.Roles.Prefix = rolePrefix
	c.Roles.ReaderRole = readerRole
	c.Roles.BaselineRole = "pathql" // unused by the test (pool is set directly)
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
	return postBody(t, srv, map[string]any{"query": query}, hdr)
}

// postBody POSTs an arbitrary request body (query plus optional params/paths) so
// write tests can send PATH hints and parameters.
func postBody(t *testing.T, srv *httptest.Server, body map[string]any, hdr map[string]string) e2eResp {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/pathql", strings.NewReader(string(raw)))
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
	q := "SELECT id, owner, body FROM " + docs + " ORDER BY id"

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

	t.Run("read-only tx blocks writes", func(t *testing.T) {
		ins := fmt.Sprintf("INSERT INTO %s (id, owner, body) VALUES (999, 'x', 'should-not-persist') RETURNING id", docs)
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

	q := "SELECT id, owner, body FROM " + env.docsTable + " ORDER BY id"

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

	q := "SELECT id, owner, body FROM " + env.docsTable

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

// TestE2EWrites exercises write support end to end against a live PostgreSQL:
// it grants the reader role write access on the demo table, adds RLS WITH CHECK
// policies, enables writes, then asserts that an INSERT ... RETURNING returns the
// new row, a write without RETURNING returns an affected count, a cross-tenant
// write is blocked by WITH CHECK, and an over-cap write is rolled back.
func TestE2EWrites(t *testing.T) {
	env := setupE2E(t)

	docs := env.docsTable
	reader := cfg.Roles.ReaderRole
	bg := context.Background()
	exec := func(q string) {
		t.Helper()
		if _, err := env.pool.DB.ExecContext(bg, q); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, q)
		}
	}

	// Grant writes to the reader group and default owner to the connected role so
	// the client never has to send it. Then add the per-command WITH CHECK
	// policies that constrain which rows a caller may create or change.
	exec(fmt.Sprintf(`GRANT INSERT, UPDATE, DELETE ON %s TO %s`, docs, reader))
	exec(fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN owner SET DEFAULT current_user`, docs))
	exec(fmt.Sprintf(`CREATE POLICY %s_ins ON %s FOR INSERT TO %s WITH CHECK (owner = current_user)`, docs, docs, reader))
	exec(fmt.Sprintf(`CREATE POLICY %s_upd ON %s FOR UPDATE TO %s USING (owner = current_user) WITH CHECK (owner = current_user)`, docs, docs, reader))
	exec(fmt.Sprintf(`CREATE POLICY %s_del ON %s FOR DELETE TO %s USING (owner = current_user)`, docs, docs, reader))

	cfg.Security.Writes = "on"
	cfg.Security.ReadOnly = false

	srv := serveE2E(t)
	defer srv.Close()

	hdr := map[string]string{"X-API-Key": e2eAPIKeyAlice}

	t.Run("insert returning the new row", func(t *testing.T) {
		r := postBody(t, srv, map[string]any{
			"query": fmt.Sprintf("INSERT INTO %s (id, body) VALUES (100, 'alice-new') RETURNING id, owner, body", docs),
			"paths": map[string]string{"$": "$"},
		}, hdr)
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, "alice-new") {
			t.Errorf("expected the returned row, got %s", r.body)
		}
		var n int
		if err := env.pool.DB.GetContext(bg, &n, "SELECT count(*) FROM "+docs+" WHERE id = 100"); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if n != 1 {
			t.Fatalf("row 100 not persisted (count=%d)", n)
		}
	})

	t.Run("insert without returning -> affected count", func(t *testing.T) {
		r := post(t, srv, fmt.Sprintf("INSERT INTO %s (id, body) VALUES (102, 'alice-two')", docs), hdr)
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, `"affected":1`) {
			t.Errorf("expected affected count, got %s", r.body)
		}
	})

	t.Run("update without returning -> affected count", func(t *testing.T) {
		r := post(t, srv, fmt.Sprintf("UPDATE %s SET body = 'edited' WHERE id = 100", docs), hdr)
		if r.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", r.status, r.body)
		}
		if !strings.Contains(r.body, `"affected":1`) {
			t.Errorf("expected affected count, got %s", r.body)
		}
	})

	t.Run("cross-tenant write blocked by WITH CHECK", func(t *testing.T) {
		// owner != current_user violates the INSERT WITH CHECK policy, so the write
		// is rejected and nothing persists.
		r := post(t, srv, fmt.Sprintf("INSERT INTO %s (id, owner, body) VALUES (103, 'someone_else', 'x') RETURNING id", docs), hdr)
		if r.status == http.StatusOK {
			t.Fatalf("cross-tenant write unexpectedly succeeded: %s", r.body)
		}
		var n int
		if err := env.pool.DB.GetContext(bg, &n, "SELECT count(*) FROM "+docs+" WHERE id = 103"); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if n != 0 {
			t.Fatalf("WITH CHECK enforcement failed: row 103 was inserted")
		}
	})

	t.Run("over-cap write rolled back", func(t *testing.T) {
		// Alice owns several rows (the two seeded plus those inserted above), so an
		// unqualified UPDATE affects more than one row. With the cap at 1 it is
		// rolled back before commit.
		cfg.Limits.MaxAffectedRows = 1
		defer func() { cfg.Limits.MaxAffectedRows = 0 }()

		r := post(t, srv, fmt.Sprintf("UPDATE %s SET body = 'capped'", docs), hdr)
		if r.status != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s, want 400", r.status, r.body)
		}
		if !strings.Contains(r.body, "exceeds the configured limit") {
			t.Errorf("unexpected body: %s", r.body)
		}
		// Nothing was changed: no row has the 'capped' body.
		var n int
		if err := env.pool.DB.GetContext(bg, &n, "SELECT count(*) FROM "+docs+" WHERE body = 'capped'"); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if n != 0 {
			t.Fatalf("over-cap write was not rolled back: %d rows changed", n)
		}
	})
}

// basicAuth builds an HTTP Basic Authorization header value.
func basicAuth(user, pass string) string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

// TestE2ECostCeiling exercises the proactive cost ceiling against a real planner:
// a query whose EXPLAIN estimate exceeds the bound is rejected with 400 before it
// runs, and a normal query passes once the bound is generous.
func TestE2ECostCeiling(t *testing.T) {
	env := setupE2E(t)
	srv := serveE2E(t)
	defer srv.Close()

	hdr := map[string]string{"X-API-Key": e2eAPIKeyAlice}

	// A tiny row ceiling rejects any non-trivial query before it runs: the planner
	// estimates generate_series(1, 100000) at far more than one row.
	cfg.Limits.MaxEstimatedRows = 1
	r := post(t, srv, "SELECT g FROM generate_series(1, 100000) AS g", hdr)
	if r.status != http.StatusBadRequest {
		t.Fatalf("over-budget query: status = %d, body = %q, want 400", r.status, r.body)
	}
	if !strings.Contains(r.body, "exceeds the configured limit") {
		t.Errorf("over-budget body = %q, want the cost-ceiling message", r.body)
	}
	if strings.Contains(r.body, "100000") {
		t.Errorf("response leaked the row estimate to the client: %q", r.body)
	}

	// With a generous ceiling, a normal query runs to completion.
	cfg.Limits.MaxEstimatedRows = 1_000_000
	cfg.Limits.MaxEstimatedCost = 0
	r = post(t, srv, "SELECT id FROM "+env.docsTable+" ORDER BY id", hdr)
	if r.status != http.StatusOK {
		t.Fatalf("within-budget query: status = %d, body = %q, want 200", r.status, r.body)
	}
}
