// Package config loads, defaults, expands and validates the pathql-server
// configuration. It fails closed: Load returns an error rather than a
// partially-usable Config whenever anything is missing or invalid.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/mevdschee/pathql-go/internal/sqlgate"
)

// Config is the top-level server configuration.
type Config struct {
	Driver  string `toml:"driver"` // required
	DSN     string `toml:"dsn"`    // shared connection string; required when identity_kind is "none", supports ${ENV}
	Listen  string `toml:"listen"` // default ":8000"
	Verbose bool   `toml:"verbose"`

	Database Database `toml:"database"`
	Security Security `toml:"security"`
	Auth     Auth     `toml:"auth"`
	Limits   Limits   `toml:"limits"`
	Timeouts Timeouts `toml:"timeouts"`
	Cache    Cache    `toml:"cache"`
	TLS      TLS      `toml:"tls"`
	CORS     CORS     `toml:"cors"`
	Roles    Roles    `toml:"roles"`
}

// Database holds connection-pool sizing.
type Database struct {
	MaxOpenConns      int `toml:"max_open_conns"`        // default 50; seed for the per-role pool default
	MaxIdleConns      int `toml:"max_idle_conns"`        // default 10; seed
	ConnMaxLifetimeMs int `toml:"conn_max_lifetime_ms"`  // default 300000 (5m); seed
	ConnMaxIdleTimeMs int `toml:"conn_max_idle_time_ms"` // default 60000 (1m); seed
	// MaxTotalBackends is the hard ceiling on simultaneous database connections
	// across all per-role pools, enforced by a shared semaphore. Config only:
	// never exposed by the admin API. Default 200.
	MaxTotalBackends int `toml:"max_total_backends"`
}

// Security holds auth-table and RLS settings.
type Security struct {
	AuthTablePrefix string   `toml:"auth_table_prefix"` // default "pathql_auth_"
	ReadOnly        bool     `toml:"read_only"`
	TrustedProxies  []string `toml:"trusted_proxies"`
	// AllowIPs and DenyIPs are the optional IP firewall lists (CIDRs or bare IPs),
	// evaluated against the resolved client IP for every route. A request from a
	// DenyIPs address is rejected with 403; if AllowIPs is non-empty, only its
	// addresses are admitted (default-deny). Both empty disables the firewall.
	AllowIPs []string `toml:"allow_ips"`
	DenyIPs  []string `toml:"deny_ips"`
	// MetricsUser is the app_user identity allowed to read GET /metrics on the
	// main listener; that principal may ONLY read metrics. Empty disables the
	// metrics endpoint entirely (fail closed). Default "metrics".
	MetricsUser string `toml:"metrics_user"`
	// StartupChecks controls the database hardening self-check run at startup:
	// "off" skips it, "warn" (default) logs findings, "enforce" refuses to start
	// on a critical finding (a superuser or BYPASSRLS role, write privileges, or
	// - under login_role - a readable table with no row-level security).
	StartupChecks string `toml:"startup_checks"`
	// IdentityKind selects the connection model and whether row-level security
	// applies:
	//   "none" (default) connects through a single shared pool (the top-level
	//     dsn). No per-caller identity reaches the database, so there is no RLS
	//     isolation: every authenticated caller runs as the same database role.
	//     Simple to set up and the development/single-tenant on-ramp; auth is
	//     optional.
	//   "login_role" connects as the caller's own database role and policies read
	//     current_user (unforgeable; see ROLE_MANAGEMENT_PLAN.md). This is how RLS
	//     isolation is enforced. Hardened, but requires per-role provisioning.
	IdentityKind string `toml:"identity_kind"`
	// AdminUser is the app_user identity allowed on the /admin/* routes; that
	// principal may only use admin routes. Empty disables them (fail closed).
	AdminUser string `toml:"admin_user"`
	// SQLGate is the optional pre-execution SQL validator (internal/sqlgate):
	// "off" (default) accepts any query; "on" rejects queries that are not a
	// single read-only statement over non-catalog objects (no stacked
	// statements, no SET/SHOW/EXPLAIN/COPY/DDL/DML, no pg_*/information_schema).
	// It is defense in depth on top of the read-only transaction and the grants.
	// The value is a string so stricter modes can be added later.
	SQLGate string `toml:"sql_gate"`
	// XSRF enables double-submit-cookie CSRF protection: "off" (default) or "on".
	// When "on", state-changing requests (POST/PUT/PATCH/DELETE) must echo the
	// XSRF-TOKEN cookie in an X-XSRF-TOKEN header. Defense in depth for browser
	// deployments that authenticate with cookies or HTTP Basic.
	XSRF string `toml:"xsrf"`
}

// Auth selects the enabled authentication methods.
type Auth struct {
	Methods      []string `toml:"methods"`        // subset of {"apikey","basic","jwt"}; empty = auth disabled
	APIKeyHeader string   `toml:"api_key_header"` // default "X-API-Key"
	// JWT settings (used when "jwt" is in Methods).
	JWTAlgorithms  []string `toml:"jwt_algorithms"`   // e.g. ["RS256"] or ["HS256"]
	JWTJWKSURL     string   `toml:"jwt_jwks_url"`     // required for RS/ES algorithms
	JWTIssuer      string   `toml:"jwt_issuer"`       // expected iss ("" = skip)
	JWTAudience    string   `toml:"jwt_audience"`     // expected aud ("" = skip)
	JWTUserClaim   string   `toml:"jwt_user_claim"`   // default "sub"
	JWTHS256Secret string   `toml:"jwt_hs256_secret"` // ${ENV}-expandable; secret; required for HS256
	RequireUserRow bool     `toml:"require_user_row"`
}

// Limits holds resource/abuse caps.
type Limits struct {
	MaxQueryMs           int   `toml:"max_query_ms"`            // default 5000 (parsed; DB-side enforcement is Phase 3)
	MaxBodyBytes         int64 `toml:"max_body_bytes"`          // default 1048576
	MaxResponseBytes     int64 `toml:"max_response_bytes"`      // default 10485760 (10 MiB); 0 = unlimited. Caps the encoded JSON response.
	MaxConcurrentPerUser int   `toml:"max_concurrent_per_user"` // default 10
	MaxConcurrentGlobal  int   `toml:"max_concurrent_global"`   // default 200
	MaxRequestsPerMinIP  int   `toml:"max_requests_per_min_ip"` // default 120
	// MaxAuthFailuresPerMin caps authentication failures per credential
	// (API-key prefix / Basic username / client IP) per minute before further
	// attempts are locked out with 429. 0 disables. Default 60.
	MaxAuthFailuresPerMin int `toml:"max_auth_failures_per_min"`
	// WorkMemKB, when > 0, sets a transaction-local work_mem (in kB) for each
	// query so a single sort/hash cannot consume unbounded memory. 0 leaves the
	// server default. Default 0.
	WorkMemKB int `toml:"work_mem_kb"`
	// MaxEstimatedCost, when > 0, makes the server EXPLAIN each query first and
	// reject (400) one whose PostgreSQL planner estimated total cost exceeds this.
	// 0 disables. PostgreSQL only.
	MaxEstimatedCost float64 `toml:"max_estimated_cost"`
	// MaxEstimatedRows, when > 0, rejects a query whose planner estimated output
	// row count exceeds this (same EXPLAIN pre-check). 0 disables. PostgreSQL only.
	MaxEstimatedRows int64 `toml:"max_estimated_rows"`
}

// Cache configures the in-process abuse-protection / JWKS cache. The cache is
// always the embedded, memory-bounded backend; there is no pluggable backend.
type Cache struct {
	MemoryMB int    `toml:"memory_mb"` // default 64
	AuthTTL  string `toml:"auth_ttl"`  // duration string, default "30s"
	JWKSTTL  string `toml:"jwks_ttl"`  // duration string, default "1h"
	// Parsed in Load (not decoded from TOML) so they cannot fail later.
	AuthTTLDuration time.Duration `toml:"-"`
	JWKSTTLDuration time.Duration `toml:"-"`
}

// TLS configures optional TLS termination on the public listener.
type TLS struct {
	Enabled      bool   `toml:"enabled"`       // default false
	CertFile     string `toml:"cert_file"`     // required when Enabled
	KeyFile      string `toml:"key_file"`      // required when Enabled
	HSTS         bool   `toml:"hsts"`          // default true
	RedirectHTTP string `toml:"redirect_http"` // optional addr, e.g. ":8080" -> 301 to https
}

// CORS configures cross-origin access.
type CORS struct {
	AllowedOrigins []string `toml:"allowed_origins"` // explicit list; never "*" with credentials
}

// Roles configures the per-role connection model and role synchronization, used
// only when security.identity_kind = "login_role". The server connects as each
// caller's own database role so RLS policies read an unforgeable current_user.
type Roles struct {
	// BaseDSN is the connection string WITHOUT a user, for example
	// "host=db port=5432 dbname=pathql sslmode=disable". The server appends
	// "user=<role>" and the role's derived password to open a connection
	// authenticated as a specific role. Supports ${ENV} expansion. Required.
	BaseDSN string `toml:"base_dsn"`
	// BaselineRole is the role the server connects as for pre-auth work (reading
	// the auth tables) before the caller is known. Default "pathql_auth".
	BaselineRole string `toml:"baseline_role"`
	// Prefix is the managed login-role name prefix: a user with id N maps to role
	// "<Prefix>N". Must match ^[a-z_][a-z0-9_]*$. Default "pathql_r_".
	Prefix string `toml:"prefix"`
	// ReaderRole is the group role granting read access that every managed role is
	// a member of. Default "pathql_readers".
	ReaderRole string `toml:"reader_role"`
	// WarmPoolLimit caps how many per-role pools keep a warm idle connection
	// (LRU). Config only, never exposed by the admin API. Default 64.
	WarmPoolLimit int `toml:"warm_pool_limit"`
	// PasswordSecret is the master secret each role password is derived from
	// (HMAC-SHA256 of the role name). Per-role connections authenticate with this
	// derived password, so pair it with scram-sha-256 in pg_hba.conf for
	// production. Required in login_role mode. ${ENV}-expandable; keep it out of
	// the file.
	PasswordSecret string `toml:"password_secret"`
}

// Timeouts holds HTTP server timeouts in milliseconds.
type Timeouts struct {
	ReadMs  int `toml:"read_ms"`  // default 10000
	WriteMs int `toml:"write_ms"` // default 30000
	IdleMs  int `toml:"idle_ms"`  // default 60000
}

// authTablePrefixRe constrains the prefix because it is interpolated into table
// names; it must be a safe SQL identifier fragment.
var authTablePrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// rolePrefixRe constrains the managed-role prefix; generated role names are
// lowercase identifiers (prefix plus the numeric user id).
var rolePrefixRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// sqlIdentRe validates a bare SQL identifier used as a role name in config.
var sqlIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envTokenRe matches ${VAR} tokens for secret/DSN expansion.
var envTokenRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load decodes a TOML config file, applies defaults to zero-valued fields,
// expands ${ENV} tokens in the secrets it carries, then validates. Returns a
// usable *Config or an error (fail closed).
func Load(path string) (*Config, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("config: load %q: %w", path, err)
	}

	// tls.hsts defaults to true; same unset-vs-false distinction as above.
	if !md.IsDefined("tls", "hsts") {
		cfg.TLS.HSTS = true
	}

	cfg.applyDefaults()

	// Expand ${ENV} tokens in the shared DSN, the JWT HS256 secret, the per-role
	// base DSN and the role password secret so secrets stay out of the config file.
	cfg.DSN = expandEnv(cfg.DSN)
	cfg.Auth.JWTHS256Secret = expandEnv(cfg.Auth.JWTHS256Secret)
	cfg.Roles.BaseDSN = expandEnv(cfg.Roles.BaseDSN)
	cfg.Roles.PasswordSecret = expandEnv(cfg.Roles.PasswordSecret)

	// A non-empty PATHQL_DSN overrides the file DSN entirely, used verbatim (no
	// further ${ENV} expansion), so a deployment can inject the connection string
	// from the environment without editing the file.
	if override := os.Getenv("PATHQL_DSN"); override != "" {
		cfg.DSN = override
	}

	// Parse cache durations now so they cannot fail at use time.
	if cfg.Cache.AuthTTLDuration, err = time.ParseDuration(cfg.Cache.AuthTTL); err != nil {
		return nil, fmt.Errorf("config: cache auth_ttl %q is not a valid duration: %w", cfg.Cache.AuthTTL, err)
	}
	if cfg.Cache.JWKSTTLDuration, err = time.ParseDuration(cfg.Cache.JWKSTTL); err != nil {
		return nil, fmt.Errorf("config: cache jwks_ttl %q is not a valid duration: %w", cfg.Cache.JWKSTTL, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDefaults fills any zero-valued field with its documented default.
func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8000"
	}

	if c.Database.MaxOpenConns == 0 {
		c.Database.MaxOpenConns = 50
	}
	if c.Database.MaxIdleConns == 0 {
		c.Database.MaxIdleConns = 10
	}
	if c.Database.ConnMaxLifetimeMs == 0 {
		c.Database.ConnMaxLifetimeMs = 300000
	}
	if c.Database.ConnMaxIdleTimeMs == 0 {
		c.Database.ConnMaxIdleTimeMs = 60000
	}
	if c.Database.MaxTotalBackends == 0 {
		c.Database.MaxTotalBackends = 200
	}

	if c.Security.AuthTablePrefix == "" {
		c.Security.AuthTablePrefix = "pathql_auth_"
	}
	if c.Security.MetricsUser == "" {
		c.Security.MetricsUser = "metrics"
	}
	if c.Security.StartupChecks == "" {
		c.Security.StartupChecks = "warn"
	}
	if c.Security.IdentityKind == "" {
		c.Security.IdentityKind = "none"
	}
	if c.Security.SQLGate == "" {
		c.Security.SQLGate = "off"
	}
	if c.Security.XSRF == "" {
		c.Security.XSRF = "off"
	}

	if c.Roles.BaselineRole == "" {
		c.Roles.BaselineRole = "pathql_auth"
	}
	if c.Roles.Prefix == "" {
		c.Roles.Prefix = "pathql_r_"
	}
	if c.Roles.ReaderRole == "" {
		c.Roles.ReaderRole = "pathql_readers"
	}
	if c.Roles.WarmPoolLimit == 0 {
		c.Roles.WarmPoolLimit = 64
	}

	if c.Auth.APIKeyHeader == "" {
		c.Auth.APIKeyHeader = "X-API-Key"
	}
	if c.Auth.JWTUserClaim == "" {
		c.Auth.JWTUserClaim = "sub"
	}

	if c.Limits.MaxQueryMs == 0 {
		c.Limits.MaxQueryMs = 5000
	}
	if c.Limits.MaxBodyBytes == 0 {
		c.Limits.MaxBodyBytes = 1048576
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = 10 << 20 // 10 MiB
	}
	if c.Limits.MaxConcurrentPerUser == 0 {
		c.Limits.MaxConcurrentPerUser = 10
	}
	if c.Limits.MaxConcurrentGlobal == 0 {
		c.Limits.MaxConcurrentGlobal = 200
	}
	if c.Limits.MaxRequestsPerMinIP == 0 {
		c.Limits.MaxRequestsPerMinIP = 120
	}
	if c.Limits.MaxAuthFailuresPerMin == 0 {
		c.Limits.MaxAuthFailuresPerMin = 60
	}

	if c.Cache.MemoryMB == 0 {
		c.Cache.MemoryMB = 64
	}
	if c.Cache.AuthTTL == "" {
		c.Cache.AuthTTL = "30s"
	}
	if c.Cache.JWKSTTL == "" {
		c.Cache.JWKSTTL = "1h"
	}

	if c.Timeouts.ReadMs == 0 {
		c.Timeouts.ReadMs = 10000
	}
	if c.Timeouts.WriteMs == 0 {
		c.Timeouts.WriteMs = 30000
	}
	if c.Timeouts.IdleMs == 0 {
		c.Timeouts.IdleMs = 60000
	}
}

// validateIPList checks that every non-empty entry in a firewall list is a valid
// CIDR or bare IP, so a typo fails closed at startup rather than silently
// admitting or blocking traffic. name is the config key, used in the error.
func validateIPList(name string, entries []string) error {
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			continue
		}
		if net.ParseIP(s) != nil {
			continue
		}
		return fmt.Errorf("config: security.%s entry %q is not a valid CIDR or IP", name, raw)
	}
	return nil
}

// expandEnv replaces every ${VAR} token with os.Getenv("VAR"); unset vars
// expand to the empty string.
func expandEnv(s string) string {
	return envTokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		name := envTokenRe.FindStringSubmatch(tok)[1]
		return os.Getenv(name)
	})
}

// validate enforces the fail-closed rules from the spec.
func (c *Config) validate() error {
	if c.Driver == "" {
		return fmt.Errorf("config: driver is required")
	}

	jwtEnabled := false
	for _, m := range c.Auth.Methods {
		switch m {
		case "apikey", "basic":
			// supported
		case "jwt":
			jwtEnabled = true
		default:
			return fmt.Errorf("config: unknown auth method %q (allowed: apikey, basic, jwt)", m)
		}
	}

	if jwtEnabled {
		if err := c.validateJWT(); err != nil {
			return err
		}
	}

	if !authTablePrefixRe.MatchString(c.Security.AuthTablePrefix) {
		return fmt.Errorf("config: auth_table_prefix %q must match %s",
			c.Security.AuthTablePrefix, authTablePrefixRe.String())
	}

	switch c.Security.StartupChecks {
	case "off", "warn", "enforce":
		// supported
	default:
		return fmt.Errorf("config: startup_checks %q must be one of off, warn, enforce", c.Security.StartupChecks)
	}

	if !sqlgate.ValidMode(c.Security.SQLGate) {
		return fmt.Errorf("config: sql_gate %q must be one of off, on", c.Security.SQLGate)
	}

	switch c.Security.XSRF {
	case "off", "on":
		// supported
	default:
		return fmt.Errorf("config: xsrf %q must be one of off, on", c.Security.XSRF)
	}

	switch c.Security.IdentityKind {
	case "none":
		// The simple on-ramp: one shared connection (the top-level dsn), no RLS.
		// Auth is optional here.
		if c.DSN == "" {
			return fmt.Errorf("config: dsn is required when identity_kind is none (empty after env expansion)")
		}
	case "login_role":
		// The server connects as each caller's own database role, so it needs a
		// principal to pick the role and a user-less base DSN to build per-role
		// connections from.
		if len(c.Auth.Methods) == 0 {
			return fmt.Errorf("config: identity_kind login_role requires at least one auth method (it needs a principal to pick a role)")
		}
		if c.Roles.BaseDSN == "" {
			return fmt.Errorf("config: identity_kind login_role requires roles.base_dsn (empty after env expansion)")
		}
		if !rolePrefixRe.MatchString(c.Roles.Prefix) {
			return fmt.Errorf("config: roles.prefix %q must match %s", c.Roles.Prefix, rolePrefixRe.String())
		}
		if !sqlIdentRe.MatchString(c.Roles.BaselineRole) {
			return fmt.Errorf("config: roles.baseline_role %q must be a valid identifier", c.Roles.BaselineRole)
		}
		if !sqlIdentRe.MatchString(c.Roles.ReaderRole) {
			return fmt.Errorf("config: roles.reader_role %q must be a valid identifier", c.Roles.ReaderRole)
		}
		if c.Roles.PasswordSecret == "" {
			return fmt.Errorf("config: identity_kind login_role requires roles.password_secret (empty after env expansion)")
		}
	default:
		return fmt.Errorf("config: identity_kind %q must be one of none, login_role", c.Security.IdentityKind)
	}

	if err := validateIPList("allow_ips", c.Security.AllowIPs); err != nil {
		return err
	}
	if err := validateIPList("deny_ips", c.Security.DenyIPs); err != nil {
		return err
	}

	if c.Limits.MaxEstimatedCost < 0 {
		return fmt.Errorf("config: limits.max_estimated_cost must be >= 0 (0 disables)")
	}
	if c.Limits.MaxEstimatedRows < 0 {
		return fmt.Errorf("config: limits.max_estimated_rows must be >= 0 (0 disables)")
	}

	if c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("config: tls.enabled requires both cert_file and key_file")
		}
	}

	return nil
}

// validateJWT enforces the JWT configuration rules when "jwt" is an enabled
// auth method. Algorithms must be present, and each requires its key material:
// HS256 needs jwt_hs256_secret, asymmetric algorithms need jwt_jwks_url.
func (c *Config) validateJWT() error {
	if len(c.Auth.JWTAlgorithms) == 0 {
		return fmt.Errorf("config: auth method jwt requires jwt_algorithms to be non-empty")
	}
	needsSecret := false
	needsJWKS := false
	for _, alg := range c.Auth.JWTAlgorithms {
		if strings.EqualFold(alg, "HS256") {
			needsSecret = true
		} else {
			// RS256/ES256/RS384/ES384/PS256/... all verify via JWKS.
			needsJWKS = true
		}
	}
	if needsSecret && c.Auth.JWTHS256Secret == "" {
		return fmt.Errorf("config: jwt algorithm HS256 requires jwt_hs256_secret (empty after env expansion)")
	}
	if needsJWKS && c.Auth.JWTJWKSURL == "" {
		return fmt.Errorf("config: jwt asymmetric algorithms require jwt_jwks_url")
	}
	return nil
}

// knownWeakRoleSecrets are placeholder, demo, and obviously-guessable values that
// must never be used as a real roles.password_secret. Keys are lowercased; the
// "login-role-demo-secret" entry is the value the bundled example ships with.
var knownWeakRoleSecrets = map[string]bool{
	"login-role-demo-secret": true,
	"changeme":               true,
	"change-me":              true,
	"changeit":               true,
	"secret":                 true,
	"password":               true,
	"password_secret":        true,
	"test":                   true,
	"demo":                   true,
	"example":                true,
}

// minRoleSecretLen is the shortest roles.password_secret the startup hardening
// check accepts without flagging it as low-entropy. The secret is the HMAC key
// every managed role's database password is derived from, so it should be a long
// random value, not a short or memorable one.
const minRoleSecretLen = 16

// WeakRoleSecretFinding reports whether the configured roles.password_secret
// looks weak, returning a human-readable finding when it does. A secret is weak
// when it is a known placeholder/demo value or is shorter than minRoleSecretLen.
// Because the secret derives every managed role's database password via HMAC, a
// guessable or checked-in value lets anyone who learns it connect as any user,
// so the operator must set a long, random secret (loaded from the environment in
// production).
func (c *Config) WeakRoleSecretFinding() (string, bool) {
	secret := c.Roles.PasswordSecret
	if knownWeakRoleSecrets[strings.ToLower(secret)] {
		return "roles.password_secret is a known placeholder/demo value: set a long, random secret (it derives every managed role's database password)", true
	}
	if len(secret) < minRoleSecretLen {
		return fmt.Sprintf("roles.password_secret is only %d characters: use at least %d random characters (it derives every managed role's database password)", len(secret), minRoleSecretLen), true
	}
	return "", false
}
