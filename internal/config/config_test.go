package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTemp writes content to a temp file in a fresh temp dir and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

// minimalValid is the smallest config that passes validation; defaults fill the
// rest. It uses the default identity_kind "none" (a single shared dsn, no RLS),
// so only driver and dsn are required and auth is optional.
const minimalValid = `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"
`

// minimalLoginRole is the smallest config that passes validation in login_role
// mode: a principal (auth method), a user-less base DSN and a role password
// secret are all required.
const minimalLoginRole = `
driver = "postgres"

[security]
identity_kind = "login_role"

[auth]
methods = ["apikey"]

[roles]
base_dsn        = "host=localhost dbname=pathql sslmode=disable"
password_secret = "test-secret"
`

func TestLoad_DecodeExplicitValues(t *testing.T) {
	content := `
driver       = "mysql"
listen       = ":9000"
verbose      = true

[database]
max_open_conns       = 7
max_idle_conns       = 3
conn_max_lifetime_ms = 1234

[security]
auth_table_prefix = "myauth_"
identity_kind     = "login_role"
read_only         = true
trusted_proxies   = ["10.0.0.0/8", "192.168.0.0/16"]

[auth]
methods        = ["apikey", "basic"]
api_key_header = "X-Key"

[roles]
base_dsn        = "host=roles dbname=pathql"
password_secret = "decode-secret"
prefix          = "myr_"

[limits]
max_query_ms       = 1000
max_body_bytes     = 2048
max_response_bytes = 42

[timeouts]
read_ms  = 11
write_ms = 22
idle_ms  = 33
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Driver", cfg.Driver, "mysql"},
		{"Listen", cfg.Listen, ":9000"},
		{"Verbose", cfg.Verbose, true},
		{"Database.MaxOpenConns", cfg.Database.MaxOpenConns, 7},
		{"Database.MaxIdleConns", cfg.Database.MaxIdleConns, 3},
		{"Database.ConnMaxLifetimeMs", cfg.Database.ConnMaxLifetimeMs, 1234},
		{"Security.AuthTablePrefix", cfg.Security.AuthTablePrefix, "myauth_"},
		{"Security.IdentityKind", cfg.Security.IdentityKind, "login_role"},
		{"Security.ReadOnly", cfg.Security.ReadOnly, true},
		{"Auth.APIKeyHeader", cfg.Auth.APIKeyHeader, "X-Key"},
		{"Roles.BaseDSN", cfg.Roles.BaseDSN, "host=roles dbname=pathql"},
		{"Roles.PasswordSecret", cfg.Roles.PasswordSecret, "decode-secret"},
		{"Roles.Prefix", cfg.Roles.Prefix, "myr_"},
		{"Limits.MaxQueryMs", cfg.Limits.MaxQueryMs, 1000},
		{"Limits.MaxBodyBytes", cfg.Limits.MaxBodyBytes, int64(2048)},
		{"Limits.MaxResponseBytes", cfg.Limits.MaxResponseBytes, int64(42)},
		{"Timeouts.ReadMs", cfg.Timeouts.ReadMs, 11},
		{"Timeouts.WriteMs", cfg.Timeouts.WriteMs, 22},
		{"Timeouts.IdleMs", cfg.Timeouts.IdleMs, 33},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if len(cfg.Security.TrustedProxies) != 2 ||
		cfg.Security.TrustedProxies[0] != "10.0.0.0/8" ||
		cfg.Security.TrustedProxies[1] != "192.168.0.0/16" {
		t.Errorf("Security.TrustedProxies = %v, want [10.0.0.0/8 192.168.0.0/16]", cfg.Security.TrustedProxies)
	}
	if len(cfg.Auth.Methods) != 2 || cfg.Auth.Methods[0] != "apikey" || cfg.Auth.Methods[1] != "basic" {
		t.Errorf("Auth.Methods = %v, want [apikey basic]", cfg.Auth.Methods)
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Listen", cfg.Listen, ":8000"},
		{"Security.IdentityKind", cfg.Security.IdentityKind, "none"},
		{"Database.MaxOpenConns", cfg.Database.MaxOpenConns, 50},
		{"Database.MaxIdleConns", cfg.Database.MaxIdleConns, 10},
		{"Database.ConnMaxLifetimeMs", cfg.Database.ConnMaxLifetimeMs, 300000},
		{"Security.AuthTablePrefix", cfg.Security.AuthTablePrefix, "pathql_auth_"},
		{"Auth.APIKeyHeader", cfg.Auth.APIKeyHeader, "X-API-Key"},
		{"Limits.MaxQueryMs", cfg.Limits.MaxQueryMs, 5000},
		{"Limits.MaxBodyBytes", cfg.Limits.MaxBodyBytes, int64(1048576)},
		{"Limits.MaxResponseBytes", cfg.Limits.MaxResponseBytes, int64(10 << 20)},
		{"Timeouts.ReadMs", cfg.Timeouts.ReadMs, 10000},
		{"Timeouts.WriteMs", cfg.Timeouts.WriteMs, 30000},
		{"Timeouts.IdleMs", cfg.Timeouts.IdleMs, 60000},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("default %s = %v, want %v", c.name, c.got, c.want)
		}
	}

	// Zero-valued bools stay as-is (no spurious defaults).
	if cfg.Verbose {
		t.Errorf("Verbose = true, want false")
	}
	if cfg.Security.ReadOnly {
		t.Errorf("Security.ReadOnly = true, want false")
	}
}

func TestLoad_NoneModeRequiresDSN(t *testing.T) {
	// identity_kind defaults to "none", which needs a dsn.
	_, err := Load(writeTemp(t, `driver = "postgres"`))
	if err == nil || !strings.Contains(err.Error(), "dsn") {
		t.Fatalf("got %v, want error mentioning dsn", err)
	}
}

func TestLoad_LoginRoleValidation(t *testing.T) {
	cfg, err := Load(writeTemp(t, minimalLoginRole))
	if err != nil {
		t.Fatalf("valid login_role config errored: %v", err)
	}
	if cfg.Security.IdentityKind != "login_role" {
		t.Errorf("IdentityKind = %q, want login_role", cfg.Security.IdentityKind)
	}
	if cfg.Roles.BaseDSN == "" || cfg.Roles.PasswordSecret == "" {
		t.Errorf("roles not decoded: %+v", cfg.Roles)
	}

	cases := []struct{ name, content, wantMsg string }{
		{
			name:    "missing base_dsn",
			content: "driver=\"postgres\"\n[security]\nidentity_kind=\"login_role\"\n[auth]\nmethods=[\"apikey\"]\n[roles]\npassword_secret=\"x\"\n",
			wantMsg: "base_dsn",
		},
		{
			name:    "without auth methods",
			content: "driver=\"postgres\"\n[security]\nidentity_kind=\"login_role\"\n[roles]\nbase_dsn=\"host=localhost dbname=pathql\"\npassword_secret=\"x\"\n",
			wantMsg: "auth method",
		},
		{
			name:    "without password_secret",
			content: "driver=\"postgres\"\n[security]\nidentity_kind=\"login_role\"\n[auth]\nmethods=[\"apikey\"]\n[roles]\nbase_dsn=\"host=localhost dbname=pathql\"\n",
			wantMsg: "password_secret",
		},
		{
			name:    "bad roles prefix",
			content: "driver=\"postgres\"\n[security]\nidentity_kind=\"login_role\"\n[auth]\nmethods=[\"apikey\"]\n[roles]\nbase_dsn=\"host=localhost dbname=pathql\"\npassword_secret=\"x\"\nprefix=\"1bad\"\n",
			wantMsg: "roles.prefix",
		},
		{
			name:    "unknown identity_kind",
			content: "driver=\"postgres\"\ndsn=\"host=localhost dbname=pathql\"\n[security]\nidentity_kind=\"bogus\"\n",
			wantMsg: "identity_kind",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("got %v, want error containing %q", err, tc.wantMsg)
			}
		})
	}
}

func TestLoad_DSNEnvExpansion(t *testing.T) {
	t.Setenv("PATHQL_DB_PASSWORD", "s3cr3t")
	content := `
driver = "postgres"
dsn    = "host=localhost user=app password=${PATHQL_DB_PASSWORD} dbname=pathql"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	want := "host=localhost user=app password=s3cr3t dbname=pathql"
	if cfg.DSN != want {
		t.Errorf("DSN = %q, want %q", cfg.DSN, want)
	}
}

func TestLoad_PathqlDSNOverride(t *testing.T) {
	t.Setenv("PATHQL_DSN", "host=override user=u password=p dbname=d")
	content := `
driver = "postgres"
dsn    = "host=fromfile dbname=pathql"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	want := "host=override user=u password=p dbname=d"
	if cfg.DSN != want {
		t.Errorf("DSN = %q, want %q (override should replace file DSN verbatim)", cfg.DSN, want)
	}
}

func TestLoad_PathqlDSNOverride_EmptyIgnored(t *testing.T) {
	t.Setenv("PATHQL_DSN", "")
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.DSN != "host=localhost dbname=pathql" {
		t.Errorf("DSN = %q, want file value (empty override ignored)", cfg.DSN)
	}
}

func TestLoad_RolesEnvExpansion(t *testing.T) {
	t.Setenv("PATHQL_DB_PASSWORD", "s3cr3t")
	t.Setenv("PATHQL_ROLE_SECRET", "fromenv-role-secret")
	content := `
driver = "postgres"

[security]
identity_kind = "login_role"

[auth]
methods = ["apikey"]

[roles]
base_dsn        = "host=localhost user=app password=${PATHQL_DB_PASSWORD} dbname=pathql"
password_secret = "${PATHQL_ROLE_SECRET}"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	wantDSN := "host=localhost user=app password=s3cr3t dbname=pathql"
	if cfg.Roles.BaseDSN != wantDSN {
		t.Errorf("Roles.BaseDSN = %q, want %q", cfg.Roles.BaseDSN, wantDSN)
	}
	if cfg.Roles.PasswordSecret != "fromenv-role-secret" {
		t.Errorf("Roles.PasswordSecret = %q, want %q", cfg.Roles.PasswordSecret, "fromenv-role-secret")
	}
}

func TestLoad_EnvExpansion_UnsetBecomesEmpty(t *testing.T) {
	os.Unsetenv("PATHQL_MISSING_VAR")
	content := `
driver = "postgres"
dsn    = "host=localhost password=${PATHQL_MISSING_VAR} dbname=pathql"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	want := "host=localhost password= dbname=pathql"
	if cfg.DSN != want {
		t.Errorf("DSN = %q, want %q", cfg.DSN, want)
	}
}

func TestLoad_MissingFileIsError(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(filepath.Join(dir, "does-not-exist.ini"))
	if err == nil {
		t.Fatal("Load on missing file returned nil error, want error")
	}
}

func TestLoad_InvalidTOMLIsError(t *testing.T) {
	_, err := Load(writeTemp(t, "this is = = not valid toml ["))
	if err == nil {
		t.Fatal("Load on invalid TOML returned nil error, want error")
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string // substring expected in the error
	}{
		{
			name:    "empty driver",
			content: `listen = ":9000"`,
			wantMsg: "driver",
		},
		{
			name: "unknown method",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods = ["apikey", "smoke-signals"]
`,
			wantMsg: "smoke-signals",
		},
		{
			name: "jwt without algorithms is rejected",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods = ["apikey", "jwt"]
`,
			wantMsg: "jwt_algorithms",
		},
		{
			name: "auth_table_prefix starts with digit",
			content: `
driver = "postgres"

[security]
auth_table_prefix = "1bad"
`,
			wantMsg: "auth_table_prefix",
		},
		{
			name: "auth_table_prefix has invalid char",
			content: `
driver = "postgres"

[security]
auth_table_prefix = "bad-prefix"
`,
			wantMsg: "auth_table_prefix",
		},
		{
			name: "auth_table_prefix with injection chars",
			content: `
driver = "postgres"

[security]
auth_table_prefix = "x\"; DROP TABLE"
`,
			wantMsg: "auth_table_prefix",
		},
		{
			name: "unknown sql_gate mode",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[security]
sql_gate = "strict"
`,
			wantMsg: "sql_gate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.content))
			if err == nil {
				t.Fatalf("Load returned nil error, want error containing %q", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestLoad_JWTHS256Accepted(t *testing.T) {
	content := `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods          = ["jwt"]
jwt_algorithms   = ["HS256"]
jwt_hs256_secret = "topsecret"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load with valid HS256 jwt returned error: %v", err)
	}
	if len(cfg.Auth.Methods) != 1 || cfg.Auth.Methods[0] != "jwt" {
		t.Errorf("Auth.Methods = %v, want [jwt]", cfg.Auth.Methods)
	}
	if cfg.Auth.JWTUserClaim != "sub" {
		t.Errorf("JWTUserClaim = %q, want default %q", cfg.Auth.JWTUserClaim, "sub")
	}
}

func TestLoad_JWTValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{
			name: "jwt missing algorithms",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods = ["jwt"]
`,
			wantMsg: "jwt_algorithms",
		},
		{
			name: "jwt HS256 missing secret",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods        = ["jwt"]
jwt_algorithms = ["HS256"]
`,
			wantMsg: "jwt_hs256_secret",
		},
		{
			name: "jwt RS256 missing jwks url",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods        = ["jwt"]
jwt_algorithms = ["RS256"]
`,
			wantMsg: "jwt_jwks_url",
		},
		{
			name: "jwt ES256 missing jwks url",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods        = ["jwt"]
jwt_algorithms = ["ES256"]
`,
			wantMsg: "jwt_jwks_url",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.content))
			if err == nil {
				t.Fatalf("Load returned nil error, want error containing %q", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestLoad_JWTRS256WithJWKSAccepted(t *testing.T) {
	content := `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods        = ["jwt"]
jwt_algorithms = ["RS256"]
jwt_jwks_url   = "https://issuer.example/.well-known/jwks.json"
jwt_user_claim = "email"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load with RS256 + JWKS returned error: %v", err)
	}
	if cfg.Auth.JWTUserClaim != "email" {
		t.Errorf("JWTUserClaim = %q, want %q", cfg.Auth.JWTUserClaim, "email")
	}
}

func TestLoad_JWTHS256SecretEnvExpansion(t *testing.T) {
	t.Setenv("JWT_HS256_SECRET", "fromenv-secret")
	content := `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods          = ["jwt"]
jwt_algorithms   = ["HS256"]
jwt_hs256_secret = "${JWT_HS256_SECRET}"
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Auth.JWTHS256Secret != "fromenv-secret" {
		t.Errorf("JWTHS256Secret = %q, want %q", cfg.Auth.JWTHS256Secret, "fromenv-secret")
	}
}

func TestLoad_JWTHS256SecretEnvExpansion_UnsetFailsValidation(t *testing.T) {
	os.Unsetenv("JWT_HS256_SECRET_UNSET")
	content := `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods          = ["jwt"]
jwt_algorithms   = ["HS256"]
jwt_hs256_secret = "${JWT_HS256_SECRET_UNSET}"
`
	_, err := Load(writeTemp(t, content))
	if err == nil {
		t.Fatal("Load returned nil error, want error because HS256 secret is empty after expansion")
	}
	if !strings.Contains(err.Error(), "jwt_hs256_secret") {
		t.Errorf("error = %q, want substring %q", err.Error(), "jwt_hs256_secret")
	}
}

func TestLoad_ValidMethodsAccepted(t *testing.T) {
	content := `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[auth]
methods = ["apikey", "basic"]
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error for valid methods: %v", err)
	}
	if len(cfg.Auth.Methods) != 2 {
		t.Errorf("Auth.Methods = %v, want 2 entries", cfg.Auth.Methods)
	}
}

func TestLoad_DefaultAuthTablePrefixIsValid(t *testing.T) {
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Security.AuthTablePrefix != "pathql_auth_" {
		t.Errorf("AuthTablePrefix = %q, want pathql_auth_", cfg.Security.AuthTablePrefix)
	}
}

func TestLoad_NewDefaults(t *testing.T) {
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Limits.MaxConcurrentPerUser", cfg.Limits.MaxConcurrentPerUser, 10},
		{"Limits.MaxConcurrentGlobal", cfg.Limits.MaxConcurrentGlobal, 200},
		{"Limits.MaxRequestsPerMinIP", cfg.Limits.MaxRequestsPerMinIP, 120},
		{"Limits.MaxAuthFailuresPerMin", cfg.Limits.MaxAuthFailuresPerMin, 60},
		{"Security.MetricsUser", cfg.Security.MetricsUser, "metrics"},
		{"Security.StartupChecks", cfg.Security.StartupChecks, "warn"},
		{"Security.SQLGate", cfg.Security.SQLGate, "off"},
		{"Database.ConnMaxIdleTimeMs", cfg.Database.ConnMaxIdleTimeMs, 60000},
		{"Database.MaxTotalBackends", cfg.Database.MaxTotalBackends, 200},
		{"Roles.BaselineRole", cfg.Roles.BaselineRole, "pathql_auth"},
		{"Roles.Prefix", cfg.Roles.Prefix, "pathql_r_"},
		{"Roles.ReaderRole", cfg.Roles.ReaderRole, "pathql_readers"},
		{"Roles.WarmPoolLimit", cfg.Roles.WarmPoolLimit, 64},
		{"Cache.MemoryMB", cfg.Cache.MemoryMB, 64},
		{"Cache.AuthTTL", cfg.Cache.AuthTTL, "30s"},
		{"Cache.JWKSTTL", cfg.Cache.JWKSTTL, "1h"},
		{"Cache.AuthTTLDuration", cfg.Cache.AuthTTLDuration, 30 * time.Second},
		{"Cache.JWKSTTLDuration", cfg.Cache.JWKSTTLDuration, time.Hour},
		{"TLS.Enabled", cfg.TLS.Enabled, false},
		{"TLS.HSTS", cfg.TLS.HSTS, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("default %s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if len(cfg.CORS.AllowedOrigins) != 0 {
		t.Errorf("CORS.AllowedOrigins = %v, want empty", cfg.CORS.AllowedOrigins)
	}
}

func TestLoad_NewExplicitValues(t *testing.T) {
	content := `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[limits]
max_concurrent_per_user = 3
max_concurrent_global   = 50
max_requests_per_min_ip = 7

[cache]
memory_mb = 128
auth_ttl  = "45s"
jwks_ttl  = "2h30m"

[tls]
enabled       = true
cert_file     = "/etc/pathql/tls.crt"
key_file      = "/etc/pathql/tls.key"
hsts          = false
redirect_http = ":8080"

[cors]
allowed_origins = ["https://a.example", "https://b.example"]
`
	cfg, err := Load(writeTemp(t, content))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Limits.MaxConcurrentPerUser", cfg.Limits.MaxConcurrentPerUser, 3},
		{"Limits.MaxConcurrentGlobal", cfg.Limits.MaxConcurrentGlobal, 50},
		{"Limits.MaxRequestsPerMinIP", cfg.Limits.MaxRequestsPerMinIP, 7},
		{"Cache.MemoryMB", cfg.Cache.MemoryMB, 128},
		{"Cache.AuthTTL", cfg.Cache.AuthTTL, "45s"},
		{"Cache.JWKSTTL", cfg.Cache.JWKSTTL, "2h30m"},
		{"Cache.AuthTTLDuration", cfg.Cache.AuthTTLDuration, 45 * time.Second},
		{"Cache.JWKSTTLDuration", cfg.Cache.JWKSTTLDuration, 2*time.Hour + 30*time.Minute},
		{"TLS.Enabled", cfg.TLS.Enabled, true},
		{"TLS.CertFile", cfg.TLS.CertFile, "/etc/pathql/tls.crt"},
		{"TLS.KeyFile", cfg.TLS.KeyFile, "/etc/pathql/tls.key"},
		{"TLS.HSTS", cfg.TLS.HSTS, false},
		{"TLS.RedirectHTTP", cfg.TLS.RedirectHTTP, ":8080"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	if len(cfg.CORS.AllowedOrigins) != 2 ||
		cfg.CORS.AllowedOrigins[0] != "https://a.example" ||
		cfg.CORS.AllowedOrigins[1] != "https://b.example" {
		t.Errorf("CORS.AllowedOrigins = %v, want [https://a.example https://b.example]", cfg.CORS.AllowedOrigins)
	}
}

func TestLoad_BadDurationIsError(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{
			name: "bad auth_ttl",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[cache]
auth_ttl = "notaduration"
`,
			wantMsg: "auth_ttl",
		},
		{
			name: "bad jwks_ttl",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[cache]
jwks_ttl = "5 zonks"
`,
			wantMsg: "jwks_ttl",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.content))
			if err == nil {
				t.Fatalf("Load returned nil error, want error containing %q", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestLoad_TLSValidation(t *testing.T) {
	// A valid none-mode preamble so the content reaches the (last) TLS check
	// rather than failing earlier on the dsn requirement.
	const preamble = `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"
`
	tests := []struct {
		name    string
		tls     string
		wantErr bool
	}{
		{
			name: "enabled without cert/key",
			tls: `
[tls]
enabled = true
`,
			wantErr: true,
		},
		{
			name: "enabled with cert only",
			tls: `
[tls]
enabled   = true
cert_file = "/etc/pathql/tls.crt"
`,
			wantErr: true,
		},
		{
			name: "enabled with cert and key",
			tls: `
[tls]
enabled   = true
cert_file = "/etc/pathql/tls.crt"
key_file  = "/etc/pathql/tls.key"
`,
			wantErr: false,
		},
		{
			name: "disabled without cert/key ok",
			tls: `
[tls]
enabled = false
`,
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, preamble+tc.tls))
			if tc.wantErr {
				if err == nil {
					t.Fatal("Load returned nil error, want TLS validation error")
				}
				if !strings.Contains(err.Error(), "tls") {
					t.Errorf("error = %q, want substring %q", err.Error(), "tls")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load returned error: %v", err)
			}
		})
	}
}

func TestWeakRoleSecretFinding(t *testing.T) {
	withSecret := func(secret string) *Config {
		c := &Config{}
		c.Roles.PasswordSecret = secret
		return c
	}

	cases := []struct {
		name     string
		cfg      *Config
		wantWeak bool
		wantSub  string
	}{
		{
			name:     "demo placeholder secret",
			cfg:      withSecret("login-role-demo-secret"),
			wantWeak: true,
			wantSub:  "placeholder",
		},
		{
			name:     "placeholder is matched case-insensitively",
			cfg:      withSecret("ChangeMe"),
			wantWeak: true,
			wantSub:  "placeholder",
		},
		{
			name:     "short secret is low-entropy",
			cfg:      withSecret("short"),
			wantWeak: true,
			wantSub:  "characters",
		},
		{
			name:     "long random secret passes",
			cfg:      withSecret("Hh7Qe2pVx9Lr3KmZ8Nb1Tc4Wd6Yf0Sg"),
			wantWeak: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, weak := tc.cfg.WeakRoleSecretFinding()
			if weak != tc.wantWeak {
				t.Fatalf("weak = %v, want %v (finding %q)", weak, tc.wantWeak, finding)
			}
			if weak && !strings.Contains(finding, tc.wantSub) {
				t.Errorf("finding = %q, want substring %q", finding, tc.wantSub)
			}
			if !weak && finding != "" {
				t.Errorf("finding = %q, want empty when not weak", finding)
			}
		})
	}
}

func TestLoad_CostCeilingLimits(t *testing.T) {
	// Default is disabled (0).
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Limits.MaxEstimatedCost != 0 || cfg.Limits.MaxEstimatedRows != 0 {
		t.Errorf("defaults = (%v, %v), want (0, 0)", cfg.Limits.MaxEstimatedCost, cfg.Limits.MaxEstimatedRows)
	}

	// Explicit values decode.
	cfg, err = Load(writeTemp(t, minimalValid+"\n[limits]\nmax_estimated_cost = 50000.5\nmax_estimated_rows = 100000\n"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Limits.MaxEstimatedCost != 50000.5 {
		t.Errorf("MaxEstimatedCost = %v, want 50000.5", cfg.Limits.MaxEstimatedCost)
	}
	if cfg.Limits.MaxEstimatedRows != 100000 {
		t.Errorf("MaxEstimatedRows = %v, want 100000", cfg.Limits.MaxEstimatedRows)
	}

	// Negative values are rejected.
	for _, bad := range []string{"max_estimated_cost = -1", "max_estimated_rows = -1"} {
		if _, err := Load(writeTemp(t, minimalValid+"\n[limits]\n"+bad+"\n")); err == nil {
			t.Errorf("Load(%q) returned nil error, want rejection", bad)
		}
	}
}
