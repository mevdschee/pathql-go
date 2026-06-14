package db

// This file implements the login_role connection pool manager. In the
// login_role RLS model every request runs as the caller's own database role,
// so each role needs its own connection pool whose connections authenticate as
// that role. RolePools lazily creates one pool per role by appending
// "user=<role>" to a base DSN (trust/peer auth on an isolated channel, so no
// per-user password is stored), bounds the total number of backends in use
// across all pools with a global semaphore, and keeps only a limited number of
// pools warm (holding idle connections) using an LRU.
//
// pathsqlx.Open is lazy: it does not dial a connection until a query runs.
// Nothing in this file runs a query, so the manager can be fully unit tested
// without a database as long as the tests never execute a query either.

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/mevdschee/pathsqlx"
)

// roleNameRe validates a role name before it is interpolated into the DSN as
// "user=<role>". A role name comes from the resolved principal, never from
// request text, but it is validated defensively because it goes straight into
// a connection string. It matches a plain SQL identifier start and body.
var roleNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// PoolParams holds the tunable parameters applied to a single role pool. They
// map directly onto the database/sql pool setters: SetMaxOpenConns,
// SetMaxIdleConns, SetConnMaxLifetime and SetConnMaxIdleTime.
type PoolParams struct {
	MaxOpen         int
	MaxIdle         int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// rolePool is the internal per-role entry: the lazily-opened pool, any per-role
// parameter override (nil means inherit the defaults) and the last time the
// role was acquired, used by the warm-pool LRU.
type rolePool struct {
	db         *pathsqlx.DB
	override   *PoolParams
	lastUsed   time.Time
	cooledDown bool
}

// RolePools manages one lazily-created connection pool per database role for
// the login_role model. It is safe for concurrent use.
//
// A global buffered-channel semaphore caps the number of connections in use
// across all pools at once, which is the hard ceiling PostgreSQL and
// database/sql cannot enforce themselves. A warm-pool limit caps how many pools
// keep idle connections: pools beyond the limit have their idle count set to
// zero by an LRU so they retain no warm connection, but they are not evicted so
// in-flight use keeps working.
type RolePools struct {
	driver    string
	baseDSN   string
	warmLimit int

	// sem is the global weighted semaphore. Each buffered slot is one backend
	// allowed to be in use at once across every pool.
	sem chan struct{}

	// open is the pool opener, injectable so tests can avoid a real database.
	// It defaults to pathsqlx.Open.
	open func(driver, dsn string) (*pathsqlx.DB, error)

	mu       sync.Mutex
	defaults PoolParams
	pools    map[string]*rolePool
	// pending holds overrides set via SetRole for roles that have no pool yet.
	// They are applied when the pool is first created on Acquire.
	pending map[string]*PoolParams
	// password, when non-nil, supplies the connection password for a role; it is
	// appended to the DSN as "password=<value>". Nil means trust/peer auth.
	password func(role string) string
}

// UseRolePassword sets the function that supplies each role's connection
// password (login_role password auth). It must be called once at startup before
// any Acquire. A nil function leaves trust/peer auth in effect.
func (p *RolePools) UseRolePassword(fn func(role string) string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.password = fn
}

// NewRolePools creates a RolePools. driver is the sql driver name. baseDSN is a
// connection string WITHOUT a user (for example
// "host=db dbname=pathql sslmode=disable"); the role is appended as
// "user=<role>" when a pool is created. maxTotalBackends bounds the number of
// connections in use across ALL pools at once via a global semaphore. warmLimit
// bounds how many pools keep idle connections, enforced by an LRU. defaults is
// the seed PoolParams applied to each new pool that has no override.
//
// It returns an error if baseDSN is empty or maxTotalBackends is less than 1.
func NewRolePools(driver, baseDSN string, maxTotalBackends, warmLimit int, defaults PoolParams) (*RolePools, error) {
	return NewRolePoolsWithOpener(driver, baseDSN, maxTotalBackends, warmLimit, defaults, pathsqlx.Open)
}

// NewRolePoolsWithOpener is like NewRolePools but takes the pool opener as an
// explicit argument so tests can inject a fake that never dials a database. A
// nil opener falls back to pathsqlx.Open.
func NewRolePoolsWithOpener(driver, baseDSN string, maxTotalBackends, warmLimit int, defaults PoolParams, opener func(driver, dsn string) (*pathsqlx.DB, error)) (*RolePools, error) {
	if baseDSN == "" {
		return nil, fmt.Errorf("db: baseDSN must not be empty")
	}
	if maxTotalBackends < 1 {
		return nil, fmt.Errorf("db: maxTotalBackends must be >= 1, got %d", maxTotalBackends)
	}
	if opener == nil {
		opener = pathsqlx.Open
	}
	return &RolePools{
		driver:    driver,
		baseDSN:   baseDSN,
		warmLimit: warmLimit,
		sem:       make(chan struct{}, maxTotalBackends),
		open:      opener,
		defaults:  defaults,
		pools:     make(map[string]*rolePool),
	}, nil
}

// roleDSN returns baseDSN with " user=<role>" appended after validating role
// against ^[A-Za-z_][A-Za-z0-9_]*$. It is a pure helper so the DSN construction
// and the role validation can be tested directly without a manager.
func roleDSN(baseDSN, role string) (string, error) {
	if !roleNameRe.MatchString(role) {
		return "", fmt.Errorf("db: invalid role %q: must match %s", role, roleNameRe.String())
	}
	return baseDSN + " user=" + role, nil
}

// effective resolves the parameters for a pool: the per-role override if one is
// set, otherwise the defaults. It is a pure helper so the precedence rule can
// be tested in isolation.
func effective(defaults PoolParams, override *PoolParams) PoolParams {
	if override != nil {
		return *override
	}
	return defaults
}

// applyParams pushes pp onto the underlying database/sql pool. The pathsqlx.DB
// embeds *sqlx.DB which embeds *sql.DB, so the pool is reached via db.DB.DB.
func applyParams(db *pathsqlx.DB, pp PoolParams) {
	db.DB.DB.SetMaxOpenConns(pp.MaxOpen)
	db.DB.DB.SetMaxIdleConns(pp.MaxIdle)
	db.DB.DB.SetConnMaxLifetime(pp.ConnMaxLifetime)
	db.DB.DB.SetConnMaxIdleTime(pp.ConnMaxIdleTime)
}

// rolesToCoolDown decides which roles must give up their warm idle connections
// when the number of live pools exceeds warmLimit. lastUsed maps each live role
// to its last Acquire time; the returned roles are the least-recently-used ones
// beyond the limit. It is a pure helper so the LRU decision can be tested
// without a manager. A warmLimit of zero or below means no pool stays warm, so
// every role is returned; a warmLimit at or above the number of live pools
// returns none.
func rolesToCoolDown(lastUsed map[string]time.Time, warmLimit int) []string {
	if len(lastUsed) <= warmLimit {
		return nil
	}
	type entry struct {
		role string
		t    time.Time
	}
	entries := make([]entry, 0, len(lastUsed))
	for role, t := range lastUsed {
		entries = append(entries, entry{role, t})
	}
	// Oldest first; ties broken by role name for a deterministic result.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].t.Equal(entries[j].t) {
			return entries[i].role < entries[j].role
		}
		return entries[i].t.Before(entries[j].t)
	})
	keep := warmLimit
	if keep < 0 {
		keep = 0
	}
	cool := make([]string, 0, len(entries)-keep)
	for _, e := range entries[:len(entries)-keep] {
		cool = append(cool, e.role)
	}
	return cool
}

// getOrCreatePool returns the pool for role, creating it lazily on first use
// with the effective parameters. It must be called with p.mu held.
func (p *RolePools) getOrCreatePool(role string) (*rolePool, error) {
	if rp, ok := p.pools[role]; ok {
		return rp, nil
	}
	dsn, err := roleDSN(p.baseDSN, role)
	if err != nil {
		return nil, err
	}
	// password mode: append the role's password. The derived value is hex, so it
	// needs no connection-string quoting.
	if p.password != nil {
		dsn += " password=" + p.password(role)
	}
	db, err := p.open(p.driver, dsn)
	if err != nil {
		return nil, err
	}
	rp := &rolePool{db: db}
	if pp, ok := p.pending[role]; ok {
		rp.override = pp
		delete(p.pending, role)
	}
	applyParams(db, effective(p.defaults, rp.override))
	p.pools[role] = rp
	return rp, nil
}

// reconcileWarm applies the warm-pool LRU. It must be called with p.mu held.
// Pools chosen by rolesToCoolDown have MaxIdleConns forced to zero so they
// retain no idle connection; pools within the limit are restored to their
// effective MaxIdle. The pools are never evicted, so in-flight use keeps
// working.
func (p *RolePools) reconcileWarm() {
	lastUsed := make(map[string]time.Time, len(p.pools))
	for role, rp := range p.pools {
		lastUsed[role] = rp.lastUsed
	}
	cool := rolesToCoolDown(lastUsed, p.warmLimit)
	coolSet := make(map[string]struct{}, len(cool))
	for _, role := range cool {
		coolSet[role] = struct{}{}
	}
	for role, rp := range p.pools {
		if _, down := coolSet[role]; down {
			if !rp.cooledDown {
				rp.db.DB.DB.SetMaxIdleConns(0)
				rp.cooledDown = true
			}
			continue
		}
		if rp.cooledDown {
			// Restore the warm idle count from the effective params.
			rp.db.DB.DB.SetMaxIdleConns(effective(p.defaults, rp.override).MaxIdle)
			rp.cooledDown = false
		}
	}
}

// Acquire blocks until a global semaphore slot is free or ctx is done. On
// success it returns the pool authenticated as role, created lazily on first
// use with the effective params, and a release func that returns the slot to
// the semaphore. The release func is safe to call exactly once.
//
// role must match ^[A-Za-z_][A-Za-z0-9_]*$ because it is interpolated into the
// DSN as "user=<role>", otherwise an error is returned and no slot is held.
func (p *RolePools) Acquire(ctx context.Context, role string) (pool *pathsqlx.DB, release func(), err error) {
	if !roleNameRe.MatchString(role) {
		return nil, nil, fmt.Errorf("db: invalid role %q: must match %s", role, roleNameRe.String())
	}
	// Take a global semaphore slot first so the total backend ceiling holds
	// regardless of per-pool values.
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	p.mu.Lock()
	rp, err := p.getOrCreatePool(role)
	if err != nil {
		p.mu.Unlock()
		<-p.sem
		return nil, nil, err
	}
	rp.lastUsed = time.Now()
	p.reconcileWarm()
	db := rp.db
	p.mu.Unlock()

	var once sync.Once
	release = func() {
		once.Do(func() { <-p.sem })
	}
	return db, release, nil
}

// SetDefaults replaces the seed parameters and re-applies them live to every
// pool that has no per-role override. Pools with an override keep it.
func (p *RolePools) SetDefaults(pp PoolParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaults = pp
	for _, rp := range p.pools {
		if rp.override == nil {
			applyParams(rp.db, pp)
		}
	}
	// Re-apply the warm LRU because changing MaxIdle on the kept-warm pools and
	// the cooled-down pools must stay consistent.
	p.reconcileWarm()
}

// SetRole sets or clears the per-role parameter override and re-applies it live.
// A nil pp clears the override so the role inherits the current defaults. If the
// role has no pool yet the override is recorded and applied when the pool is
// created.
func (p *RolePools) SetRole(role string, pp *PoolParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rp, ok := p.pools[role]
	if !ok {
		// No live pool yet, so remember the override (or clear a remembered
		// one) and apply it when the pool is created lazily on first Acquire.
		if pp == nil {
			delete(p.pending, role)
			return
		}
		if p.pending == nil {
			p.pending = make(map[string]*PoolParams)
		}
		p.pending[role] = pp
		return
	}
	rp.override = pp
	applyParams(rp.db, effective(p.defaults, rp.override))
	p.reconcileWarm()
}

// Stats returns a snapshot of sql.DBStats for each live pool, keyed by role.
func (p *RolePools) Stats() map[string]sql.DBStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]sql.DBStats, len(p.pools))
	for role, rp := range p.pools {
		out[role] = rp.db.DB.DB.Stats()
	}
	return out
}

// Evict closes and removes the pool for role. In-flight callers holding a
// reference to the closed pool will see their queries fail, which is the
// intended behavior when a role is being removed. It is a no-op if no pool
// exists for the role.
func (p *RolePools) Evict(role string) {
	p.mu.Lock()
	rp, ok := p.pools[role]
	if ok {
		delete(p.pools, role)
	}
	delete(p.pending, role)
	p.mu.Unlock()
	if ok {
		_ = rp.db.DB.DB.Close()
	}
}

// Close closes every pool and removes them. It returns the first close error
// encountered, if any, after attempting to close all pools.
func (p *RolePools) Close() error {
	p.mu.Lock()
	pools := p.pools
	p.pools = make(map[string]*rolePool)
	p.pending = nil
	p.mu.Unlock()
	var firstErr error
	for _, rp := range pools {
		if err := rp.db.DB.DB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
