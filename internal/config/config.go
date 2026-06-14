// Package config loads, defaults, expands and validates the pathql-server
// configuration. It fails closed: Load returns an error rather than a
// partially-usable Config whenever anything is missing or invalid.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level server configuration.
type Config struct {
	Driver  string `toml:"driver"` // required
	DSN     string `toml:"dsn"`    // required; supports ${ENV} expansion
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
	// across all per-role pools (login_role mode), enforced by a shared
	// semaphore. Config only: never exposed by the admin API. Default 200.
	MaxTotalBackends int `toml:"max_total_backends"`
}

// Security holds auth-table and RLS settings.
type Security struct {
	AuthTablePrefix         string   `toml:"auth_table_prefix"`         // default "pathql_auth_"
	SessionVariable         string   `toml:"session_variable"`          // default "app.user" (parsed, Phase 3)
	ReadOnly                bool     `toml:"read_only"`                 // parsed, Phase 3
	TrustedProxies          []string `toml:"trusted_proxies"`           // parsed, Phase 5
	BlockMultipleStatements bool     `toml:"block_multiple_statements"` // default true
	// MetricsUser is the app_user identity allowed to read GET /metrics on the
	// main listener; that principal may ONLY read metrics. Empty disables the
	// metrics endpoint entirely (fail closed). Default "metrics".
	MetricsUser string `toml:"metrics_user"`
	// StartupChecks controls the database hardening self-check run at startup:
	// "off" skips it, "warn" (default) logs findings, "enforce" refuses to start
	// on a critical finding (superuser role or write privileges).
	StartupChecks string `toml:"startup_checks"`
	// IdentityKind selects how the caller's identity reaches RLS: "session_guc"
	// (default) binds app.user with set_config and policies read current_setting;
	// "login_role" connects as the caller's own database role and policies read
	// current_user (unforgeable, see ROLE_MANAGEMENT_PLAN.md).
	IdentityKind string `toml:"identity_kind"`
	// AdminUser is the app_user identity allowed on the /admin/* routes; that
	// principal may only use admin routes. Empty disables them (fail closed).
	AdminUser string `toml:"admin_user"`
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
}

// Cache configures the abuse-protection / JWKS cache backend.
type Cache struct {
	Backend  string `toml:"backend"`   // "embedded" (default). "memcached" is not implemented yet.
	Address  string `toml:"address"`   // optional, backend-specific
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

// Roles configures the login_role connection model and role synchronization.
// Only used when security.identity_kind = "login_role".
type Roles struct {
	// BaseDSN is the connection string WITHOUT a user, for example
	// "host=db port=5432 dbname=pathql sslmode=disable". The server appends
	// "user=<role>" to open a connection authenticated (trust/peer on an isolated
	// channel) as a specific role. Supports ${ENV} expansion. Required in
	// login_role mode.
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

// envTokenRe matches ${VAR} tokens for DSN expansion.
var envTokenRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load decodes a TOML config file, applies defaults to zero-valued fields,
// expands ${ENV} tokens in DSN, applies the PATHQL_DSN env override if set,
// then validates. Returns a usable *Config or an error (fail closed).
func Load(path string) (*Config, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("config: load %q: %w", path, err)
	}

	// block_multiple_statements defaults to true; only an explicit false in the
	// file may disable it. A plain zero-value default cannot distinguish "unset"
	// from "set to false", so consult the decode metadata.
	if !md.IsDefined("security", "block_multiple_statements") {
		cfg.Security.BlockMultipleStatements = true
	}
	// tls.hsts defaults to true; same unset-vs-false distinction as above.
	if !md.IsDefined("tls", "hsts") {
		cfg.TLS.HSTS = true
	}

	cfg.applyDefaults()

	// Expand ${ENV} tokens in the file-provided DSN.
	cfg.DSN = expandEnv(cfg.DSN)

	// Expand ${ENV} tokens in the JWT HS256 secret (same mechanism as DSN).
	cfg.Auth.JWTHS256Secret = expandEnv(cfg.Auth.JWTHS256Secret)

	// Expand ${ENV} tokens in the login_role base DSN (same mechanism as DSN).
	cfg.Roles.BaseDSN = expandEnv(cfg.Roles.BaseDSN)

	// A non-empty PATHQL_DSN overrides the file DSN entirely, used verbatim.
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
	if c.Security.SessionVariable == "" {
		c.Security.SessionVariable = "app.user"
	}
	if c.Security.MetricsUser == "" {
		c.Security.MetricsUser = "metrics"
	}
	if c.Security.StartupChecks == "" {
		c.Security.StartupChecks = "warn"
	}
	if c.Security.IdentityKind == "" {
		c.Security.IdentityKind = "session_guc"
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

	if c.Cache.Backend == "" {
		c.Cache.Backend = "embedded"
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
	if c.Security.IdentityKind != "login_role" && c.DSN == "" {
		return fmt.Errorf("config: dsn is required (empty after env expansion)")
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

	switch c.Security.IdentityKind {
	case "session_guc":
		// the default GUC binding; no extra requirements
	case "login_role":
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
	default:
		return fmt.Errorf("config: identity_kind %q must be one of session_guc, login_role", c.Security.IdentityKind)
	}

	switch c.Cache.Backend {
	case "embedded":
		// supported
	default:
		return fmt.Errorf("config: cache backend %q not supported yet (use embedded)", c.Cache.Backend)
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
