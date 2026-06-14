package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/mevdschee/dbml-tools/introspect"

	"github.com/mevdschee/pathql-go/internal/auth"
	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
	"github.com/mevdschee/pathql-go/internal/middleware"
)

// schemaEngine maps the configured SQL driver to a dbml-tools introspection
// engine and the schema/database name to read. ok is false for drivers whose
// schema reflection is not wired up.
func schemaEngine(driver string) (engine introspect.Engine, schemaName string, ok bool) {
	switch driver {
	case "postgres":
		return introspect.EnginePostgres, "public", true
	default:
		// MariaDB reflection needs the database name (not derivable from pathql's
		// keyword DSN here); other drivers are unsupported.
		return 0, "", false
	}
}

// SchemaEndpoint handles GET /schema. It reflects the tables, columns, primary
// keys and foreign keys the authenticated caller's database role can read and
// returns them as DBML (rendered by dbml-tools). The reflection runs on the
// caller's own connection, so in login_role mode PostgreSQL's information_schema
// naturally restricts the output to tables that role was granted, with no write
// access or DDL. It is PostgreSQL-only.
func SchemaEndpoint(w http.ResponseWriter, req *http.Request) {
	engine, schemaName, ok := schemaEngine(cfg.Driver)
	if !ok {
		writeError(w, req, http.StatusNotImplemented, "schema reflection is only available for the postgres driver", nil)
		return
	}

	var principal *auth.Principal
	if p, ok := auth.FromContext(req.Context()); ok && p != nil {
		principal = p
	}

	statementTimeout := time.Duration(cfg.Limits.MaxQueryMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(req.Context(), statementTimeout)
	defer cancel()

	queryPool, release, ok := selectQueryPool(ctx, w, req, principal)
	if !ok {
		return
	}
	defer release()

	schema, err := introspect.Introspect(ctx, queryPool.DB.DB, engine, schemaName)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeError(w, req, http.StatusServiceUnavailable, "query timed out", err)
			return
		}
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}

	dbml := introspect.GenerateDBML(schema, "PostgreSQL", false)

	// Cap the response like /pathql so a very large schema cannot exceed the
	// configured response limit.
	if cfg.Limits.MaxResponseBytes > 0 && int64(len(dbml)) > cfg.Limits.MaxResponseBytes {
		writeError(w, req, http.StatusRequestEntityTooLarge, "response too large", errResponseTooLarge)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(dbml))
}

// schemaHandler assembles the chain for GET /schema on the public listener. It
// mirrors the /pathql chain (auth, abuse limits, per-user concurrency, and the
// metrics/admin principal denials) but without the JSON body middlewares, since
// it is a parameterless GET.
func schemaHandler(c *config.Config, chain *auth.Chain, theCache cache.Cache, trustedProxies []*net.IPNet) http.Handler {
	var h http.Handler = http.HandlerFunc(SchemaEndpoint)
	h = middleware.PerUserConcurrency(c.Limits.MaxConcurrentPerUser, principalKey)(h)
	h = denyAppUser(c.Security.MetricsUser)(h)
	h = denyAppUser(c.Security.AdminUser)(h)
	if chain != nil {
		h = chain.Middleware(h)
	}
	h = middleware.BruteForceLockout(theCache, c.Limits.MaxAuthFailuresPerMin, trustedProxies)(h)
	h = metricsMiddleware(h)
	h = middleware.RateLimitPerIP(theCache, c.Limits.MaxRequestsPerMinIP, trustedProxies)(h)
	h = middleware.GlobalInflight(c.Limits.MaxConcurrentGlobal)(h)
	h = middleware.RequestID(h)
	h = middleware.CORS(c.CORS.AllowedOrigins)(h)
	if c.TLS.Enabled && c.TLS.HSTS {
		h = middleware.HSTS(h)
	}
	h = middleware.SecurityHeaders(h)
	h = middleware.Recover(h)
	return h
}
