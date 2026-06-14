//go:build e2e

// End-to-end coverage for GET /schema (DBML reflection) and GET /health against
// a live PostgreSQL. Unlike the RLS suite these run in identity_kind "none" (one
// shared connection, no login roles), so they need only CREATE TABLE, not
// CREATEROLE, and exercise the real reflection + DBML rendering path.
//
//	go test -tags e2e -run TestE2ESchema ./...
//	go test -tags e2e -run TestE2EHealthLive ./...
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
	"github.com/mevdschee/pathql-go/internal/db"
)

// setupSchemaE2E installs two related tables in identity_kind "none" mode and
// wires the package globals the handlers read. It returns the parent and child
// table names and registers cleanup.
func setupSchemaE2E(t *testing.T) (parent, child string) {
	t.Helper()

	p, err := db.OpenPool(e2eDriver, e2eDSN(), 10, 5, 5*time.Minute)
	if err != nil {
		t.Skipf("cannot open pool: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := db.Ping(ctx, p); err != nil {
		_ = db.Close(p)
		t.Skipf("PostgreSQL not reachable at %q: %v", e2eDSN(), err)
	}

	prefix := fmt.Sprintf("e2e_schema_%d_", os.Getpid())
	parent = prefix + "authors"
	child = prefix + "books"
	bg := context.Background()

	exec := func(q string) {
		t.Helper()
		if _, err := p.DB.ExecContext(bg, q); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, q)
		}
	}
	drop := func() {
		_, _ = p.DB.ExecContext(bg, "DROP TABLE IF EXISTS "+child)
		_, _ = p.DB.ExecContext(bg, "DROP TABLE IF EXISTS "+parent)
	}
	drop()
	exec(fmt.Sprintf(`CREATE TABLE %s (id bigserial PRIMARY KEY, name text NOT NULL)`, parent))
	exec(fmt.Sprintf(`CREATE TABLE %s (
		id        bigserial PRIMARY KEY,
		author_id bigint NOT NULL REFERENCES %s(id),
		title     text NOT NULL
	)`, child, parent))

	c, err := cache.NewEmbedded(16)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}

	oldCfg, oldPool, oldCache := cfg, pool, sharedCache
	cfg = schemaE2EConfig(prefix)
	pool = p
	sharedCache = c

	t.Cleanup(func() {
		drop()
		_ = db.Close(p)
		_ = c.Close()
		cfg, pool, sharedCache = oldCfg, oldPool, oldCache
	})
	return parent, child
}

// schemaE2EConfig is a "none" identity-mode config with auth disabled (allowed in
// that mode) and generous limits.
func schemaE2EConfig(prefix string) *config.Config {
	c := &config.Config{Driver: e2eDriver}
	c.Security.IdentityKind = "none"
	c.Security.AuthTablePrefix = prefix
	c.Security.ReadOnly = true
	c.Limits.MaxQueryMs = 5000
	c.Limits.MaxResponseBytes = 10 << 20
	c.Limits.MaxConcurrentPerUser = 50
	c.Limits.MaxConcurrentGlobal = 200
	c.Limits.MaxRequestsPerMinIP = 1000
	c.Cache.MemoryMB = 16
	c.Cache.JWKSTTLDuration = time.Hour
	return c
}

func TestE2ESchemaDBML(t *testing.T) {
	parent, child := setupSchemaE2E(t)

	chain, err := buildAuthChain(cfg) // nil chain: auth disabled in none mode
	if err != nil {
		t.Fatalf("buildAuthChain: %v", err)
	}
	srv := httptest.NewServer(schemaHandler(cfg, chain, sharedCache, nil))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/schema", nil)
	req.RemoteAddr = "203.0.113.10:6000"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("expected text/plain DBML, got Content-Type %q", ct)
	}
	// DBML structure: a Project header, both reflected tables, and a Ref for the FK.
	for _, want := range []string{
		"Project {",
		fmt.Sprintf("Table %q", parent),
		fmt.Sprintf("Table %q", child),
		"author_id",
		"Ref:",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("DBML missing %q\n--- DBML ---\n%s", want, body)
		}
	}
}

func TestE2EHealthLive(t *testing.T) {
	setupSchemaE2E(t)
	srv := httptest.NewServer(healthHandler(newHealthChecker(pool)))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d body=%s", resp.StatusCode, string(b))
	}
	if !strings.Contains(string(b), `"database":"up"`) {
		t.Errorf("expected database up, got %s", string(b))
	}
}
