package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/mevdschee/pathql-go/internal/auth"
	"github.com/mevdschee/pathql-go/internal/cache"
	"github.com/mevdschee/pathql-go/internal/config"
	"github.com/mevdschee/pathql-go/internal/middleware"
	"github.com/mevdschee/pathql-go/internal/roles"
)

// userAdmin writes the auth tables for the /admin/users routes. Built at startup
// over the same (baseline) connection used for auth lookups.
var userAdmin *auth.UserAdmin

// adminHandler assembles the middleware chain for an /admin/* route: the standard
// outer protections, then authentication, then authorization to the single
// AdminUser principal. An empty AdminUser makes every admin request 403 (fail
// closed), and that principal is also kept off /pathql (see publicHandler).
func adminHandler(c *config.Config, chain *auth.Chain, theCache cache.Cache, trustedProxies []*net.IPNet, h http.HandlerFunc) http.Handler {
	var handler http.Handler = h
	handler = requireAppUser(c.Security.AdminUser)(handler)
	if chain != nil {
		handler = chain.Middleware(handler)
	}
	handler = middleware.BruteForceLockout(theCache, c.Limits.MaxAuthFailuresPerMin, trustedProxies)(handler)
	handler = middleware.RateLimitPerIP(theCache, c.Limits.MaxRequestsPerMinIP, trustedProxies)(handler)
	handler = middleware.GlobalInflight(c.Limits.MaxConcurrentGlobal)(handler)
	handler = middleware.BodyLimit(c.Limits.MaxBodyBytes)(handler)
	handler = middleware.RequireContentTypeJSON(handler)
	handler = middleware.RequestID(handler)
	if c.TLS.Enabled && c.TLS.HSTS {
		handler = middleware.HSTS(handler)
	}
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.Recover(handler)
	return handler
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type adminAddUserRequest struct {
	Username       string `json:"username"`
	AppUser        string `json:"app_user"`
	Password       string `json:"password"`
	GenerateAPIKey bool   `json:"generate_api_key"`
}

type adminAddUserResponse struct {
	ID     int64  `json:"id"`
	Role   string `json:"role"`
	APIKey string `json:"api_key,omitempty"`
	Note   string `json:"note"`
}

// adminAddUser handles POST /admin/users: it inserts a user row (optionally with
// a bcrypt password for Basic and a freshly generated API key) and reports the
// managed role name that the next roles sync will create.
func adminAddUser(w http.ResponseWriter, req *http.Request) {
	var body adminAddUserRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, req, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if body.Username == "" {
		writeError(w, req, http.StatusBadRequest, "username is required", nil)
		return
	}

	passwordHash := ""
	if body.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
			return
		}
		passwordHash = string(h)
	}

	id, err := userAdmin.AddUser(req.Context(), body.Username, body.AppUser, passwordHash)
	if err != nil {
		// Most likely a duplicate username; the real cause is logged server-side.
		writeError(w, req, http.StatusBadRequest, "could not create user", err)
		return
	}

	resp := adminAddUserResponse{ID: id, Note: "role is created on the next roles sync"}
	if role, rerr := roles.RoleName(cfg.Roles.Prefix, id); rerr == nil {
		resp.Role = role
	}

	if body.GenerateAPIKey {
		key, kerr := newAPIKey()
		if kerr != nil {
			writeError(w, req, http.StatusInternalServerError, genericInternalError, kerr)
			return
		}
		sum := sha256.Sum256([]byte(key))
		if aerr := userAdmin.AddAPIKey(req.Context(), id, key[:8], sum[:], "admin-created"); aerr != nil {
			writeError(w, req, http.StatusInternalServerError, genericInternalError, aerr)
			return
		}
		resp.APIKey = key // shown once
	}

	writeJSON(w, http.StatusCreated, resp)
}

// adminDeleteUser handles DELETE /admin/users/{id}: it removes the user (and its
// API keys), evicts the role's connection pool, and reports the role that the
// next roles sync will drop.
func adminDeleteUser(w http.ResponseWriter, req *http.Request) {
	id, err := strconv.ParseInt(req.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, req, http.StatusBadRequest, "invalid user id", nil)
		return
	}
	deleted, err := userAdmin.DeleteUser(req.Context(), id)
	if err != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}
	if !deleted {
		writeError(w, req, http.StatusNotFound, "no such user", nil)
		return
	}
	resp := map[string]any{"deleted": true, "note": "run the roles sync to drop the role"}
	if role, rerr := roles.RoleName(cfg.Roles.Prefix, id); rerr == nil {
		resp["role"] = role
		if rolePools != nil {
			rolePools.Evict(role)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// adminRolesSync handles GET /admin/roles/sync: it returns the exact DDL needed
// to make the database login roles match the users table, for a cron job to
// apply. The server never runs this DDL itself.
func adminRolesSync(w http.ResponseWriter, req *http.Request) {
	plan, err := roles.LoadAndCompute(req.Context(), pool.DB, cfg.Security.AuthTablePrefix, cfg.Roles.Prefix, cfg.Roles.ReaderRole)
	if err != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"create":       plan.Create,
		"grant_reader": plan.GrantReader,
		"drop":         plan.Drop,
		"ddl":          plan.DDL,
	})
}

// newAPIKey returns a fresh random API key (48 hex chars from 24 random bytes).
// The caller stores only its prefix and sha-256 hash.
func newAPIKey() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
