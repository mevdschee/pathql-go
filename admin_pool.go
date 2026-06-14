package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/mevdschee/pathql-go/internal/db"
	"github.com/mevdschee/pathql-go/internal/roles"
)

// poolStore persists the runtime-tunable pool parameters (login_role mode only).
var poolStore *db.PoolStore

// configSeed is the pool default seeded from config.ini on first start.
func configSeed() db.PoolParams {
	return db.PoolParams{
		MaxOpen:         cfg.Database.MaxOpenConns,
		MaxIdle:         cfg.Database.MaxIdleConns,
		ConnMaxLifetime: time.Duration(cfg.Database.ConnMaxLifetimeMs) * time.Millisecond,
		ConnMaxIdleTime: time.Duration(cfg.Database.ConnMaxIdleTimeMs) * time.Millisecond,
	}
}

// loadPoolSettings loads the persisted global pool defaults (seeding them from
// config on first start) and the per-user overrides, and applies them to the
// live pool manager. Best effort: a failure is logged and the in-memory seed
// defaults remain in force.
func loadPoolSettings() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gp, ok, err := poolStore.LoadGlobal(ctx)
	if err != nil {
		log.Printf("WARNING: pool settings load failed: %v", err)
		return
	}
	if !ok {
		gp = configSeed()
		if serr := poolStore.SaveGlobal(ctx, gp); serr != nil {
			log.Printf("WARNING: pool settings seed failed: %v", serr)
		}
	}
	rolePools.SetDefaults(gp)

	overrides, oerr := poolStore.LoadOverrides(ctx)
	if oerr != nil {
		log.Printf("WARNING: pool overrides load failed: %v", oerr)
		return
	}
	for id, pp := range overrides {
		if role, rerr := roles.RoleName(cfg.Roles.Prefix, id); rerr == nil {
			p := pp
			rolePools.SetRole(role, &p)
		}
	}
}

// poolParamsDTO is the JSON shape for pool parameters (durations in ms).
type poolParamsDTO struct {
	MaxOpen           int   `json:"max_open"`
	MaxIdle           int   `json:"max_idle"`
	ConnMaxLifetimeMs int64 `json:"conn_max_lifetime_ms"`
	ConnMaxIdleTimeMs int64 `json:"conn_max_idle_time_ms"`
}

func (d poolParamsDTO) toParams() db.PoolParams {
	return db.PoolParams{
		MaxOpen:         d.MaxOpen,
		MaxIdle:         d.MaxIdle,
		ConnMaxLifetime: time.Duration(d.ConnMaxLifetimeMs) * time.Millisecond,
		ConnMaxIdleTime: time.Duration(d.ConnMaxIdleTimeMs) * time.Millisecond,
	}
}

func dtoFromParams(p db.PoolParams) poolParamsDTO {
	return poolParamsDTO{
		MaxOpen:           p.MaxOpen,
		MaxIdle:           p.MaxIdle,
		ConnMaxLifetimeMs: p.ConnMaxLifetime.Milliseconds(),
		ConnMaxIdleTimeMs: p.ConnMaxIdleTime.Milliseconds(),
	}
}

// validatePoolParams enforces the bounds the admin API may set within. The
// per-pool max never exceeds the config-only max_total_backends ceiling.
func validatePoolParams(p db.PoolParams, maxTotal int) error {
	switch {
	case p.MaxOpen < 1:
		return errors.New("max_open must be >= 1")
	case maxTotal > 0 && p.MaxOpen > maxTotal:
		return fmt.Errorf("max_open must be <= max_total_backends (%d)", maxTotal)
	case p.MaxIdle < 0:
		return errors.New("max_idle must be >= 0")
	case p.MaxIdle > p.MaxOpen:
		return errors.New("max_idle must be <= max_open")
	case p.ConnMaxLifetime < 0 || p.ConnMaxIdleTime < 0:
		return errors.New("durations must be >= 0")
	}
	return nil
}

// notLoginRole rejects pool-tuning requests when the server is not in login_role
// mode (there are no per-role pools to tune).
func notLoginRole(w http.ResponseWriter, req *http.Request) {
	writeError(w, req, http.StatusBadRequest, "pool tuning requires identity_kind=login_role", nil)
}

// statsJSON renders sql.DBStats per role into a compact JSON-friendly map.
func statsJSON(all map[string]sql.DBStats) map[string]any {
	out := make(map[string]any, len(all))
	for role, s := range all {
		out[role] = map[string]any{
			"max_open_connections": s.MaxOpenConnections,
			"open_connections":     s.OpenConnections,
			"in_use":               s.InUse,
			"idle":                 s.Idle,
			"wait_count":           s.WaitCount,
			"wait_duration_ms":     s.WaitDuration.Milliseconds(),
		}
	}
	return out
}

// adminGetPool handles GET /admin/pool: the effective global defaults, the
// config-only ceilings, and live per-pool stats.
func adminGetPool(w http.ResponseWriter, req *http.Request) {
	if rolePools == nil {
		notLoginRole(w, req)
		return
	}
	gp, ok, err := poolStore.LoadGlobal(req.Context())
	if err != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}
	if !ok {
		gp = configSeed()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"global":             dtoFromParams(gp),
		"max_total_backends": cfg.Database.MaxTotalBackends,
		"warm_pool_limit":    cfg.Roles.WarmPoolLimit,
		"pools":              statsJSON(rolePools.Stats()),
	})
}

// adminPutPool handles PUT /admin/pool: set the global defaults, persist them,
// and apply them live to every pool without an override.
func adminPutPool(w http.ResponseWriter, req *http.Request) {
	if rolePools == nil {
		notLoginRole(w, req)
		return
	}
	var dto poolParamsDTO
	if err := json.NewDecoder(req.Body).Decode(&dto); err != nil {
		writeError(w, req, http.StatusBadRequest, "invalid request body", err)
		return
	}
	pp := dto.toParams()
	if err := validatePoolParams(pp, cfg.Database.MaxTotalBackends); err != nil {
		writeError(w, req, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := poolStore.SaveGlobal(req.Context(), pp); err != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, err)
		return
	}
	rolePools.SetDefaults(pp)
	writeJSON(w, http.StatusOK, map[string]any{"global": dtoFromParams(pp)})
}

// adminPutUserPool handles PUT /admin/users/{id}/pool: set a per-user override,
// persist it, and apply it live to that user's pool.
func adminPutUserPool(w http.ResponseWriter, req *http.Request) {
	if rolePools == nil {
		notLoginRole(w, req)
		return
	}
	id, err := strconv.ParseInt(req.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, req, http.StatusBadRequest, "invalid user id", nil)
		return
	}
	var dto poolParamsDTO
	if derr := json.NewDecoder(req.Body).Decode(&dto); derr != nil {
		writeError(w, req, http.StatusBadRequest, "invalid request body", derr)
		return
	}
	pp := dto.toParams()
	if verr := validatePoolParams(pp, cfg.Database.MaxTotalBackends); verr != nil {
		writeError(w, req, http.StatusBadRequest, verr.Error(), nil)
		return
	}
	if serr := poolStore.SaveOverride(req.Context(), id, &pp); serr != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, serr)
		return
	}
	if role, rerr := roles.RoleName(cfg.Roles.Prefix, id); rerr == nil {
		rolePools.SetRole(role, &pp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "override": dtoFromParams(pp)})
}

// adminDeleteUserPool handles DELETE /admin/users/{id}/pool: clear a per-user
// override so the user inherits the global default again.
func adminDeleteUserPool(w http.ResponseWriter, req *http.Request) {
	if rolePools == nil {
		notLoginRole(w, req)
		return
	}
	id, err := strconv.ParseInt(req.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, req, http.StatusBadRequest, "invalid user id", nil)
		return
	}
	if serr := poolStore.SaveOverride(req.Context(), id, nil); serr != nil {
		writeError(w, req, http.StatusInternalServerError, genericInternalError, serr)
		return
	}
	if role, rerr := roles.RoleName(cfg.Roles.Prefix, id); rerr == nil {
		rolePools.SetRole(role, nil)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "override": nil})
}
