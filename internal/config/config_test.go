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

// minimalValid is the smallest config that passes validation; defaults fill the rest.
const minimalValid = `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"
`

func TestLoad_DecodeExplicitValues(t *testing.T) {
	content := `
driver       = "mysql"
dsn          = "user:pass@/db"
listen       = ":9000"
verbose      = true

[database]
max_open_conns       = 7
max_idle_conns       = 3
conn_max_lifetime_ms = 1234

[security]
auth_table_prefix = "myauth_"
session_variable  = "pathql.user"
read_only         = true
trusted_proxies   = ["10.0.0.0/8", "192.168.0.0/16"]

[auth]
methods        = ["apikey", "basic"]
api_key_header = "X-Key"

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
		{"DSN", cfg.DSN, "user:pass@/db"},
		{"Listen", cfg.Listen, ":9000"},
		{"Verbose", cfg.Verbose, true},
		{"Database.MaxOpenConns", cfg.Database.MaxOpenConns, 7},
		{"Database.MaxIdleConns", cfg.Database.MaxIdleConns, 3},
		{"Database.ConnMaxLifetimeMs", cfg.Database.ConnMaxLifetimeMs, 1234},
		{"Security.AuthTablePrefix", cfg.Security.AuthTablePrefix, "myauth_"},
		{"Security.SessionVariable", cfg.Security.SessionVariable, "pathql.user"},
		{"Security.ReadOnly", cfg.Security.ReadOnly, true},
		{"Auth.APIKeyHeader", cfg.Auth.APIKeyHeader, "X-Key"},
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
		{"Database.MaxOpenConns", cfg.Database.MaxOpenConns, 50},
		{"Database.MaxIdleConns", cfg.Database.MaxIdleConns, 10},
		{"Database.ConnMaxLifetimeMs", cfg.Database.ConnMaxLifetimeMs, 300000},
		{"Security.AuthTablePrefix", cfg.Security.AuthTablePrefix, "pathql_auth_"},
		{"Security.SessionVariable", cfg.Security.SessionVariable, "app.user"},
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

	// Zero-valued bools and empty slices stay as-is (no spurious defaults).
	if cfg.Verbose {
		t.Errorf("Verbose = true, want false")
	}
	if cfg.Security.ReadOnly {
		t.Errorf("Security.ReadOnly = true, want false")
	}
	if len(cfg.Auth.Methods) != 0 {
		t.Errorf("Auth.Methods = %v, want empty", cfg.Auth.Methods)
	}
}

func TestLoad_EnvExpansion(t *testing.T) {
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

func TestLoad_EnvExpansion_UnsetBecomesEmpty(t *testing.T) {
	// Ensure the var is not set in the environment.
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

func TestLoad_PathqlDSNOverride_UsedVerbatim(t *testing.T) {
	// The override is used verbatim: no ${ENV} expansion is applied to it.
	t.Setenv("SHOULD_NOT_EXPAND", "EXPANDED")
	t.Setenv("PATHQL_DSN", "host=x password=${SHOULD_NOT_EXPAND}")
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	want := "host=x password=${SHOULD_NOT_EXPAND}"
	if cfg.DSN != want {
		t.Errorf("DSN = %q, want %q (override must be verbatim)", cfg.DSN, want)
	}
}

func TestLoad_PathqlDSNOverride_EmptyIgnored(t *testing.T) {
	// An empty PATHQL_DSN must NOT override the file value.
	t.Setenv("PATHQL_DSN", "")
	cfg, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.DSN != "host=localhost dbname=pathql" {
		t.Errorf("DSN = %q, want file value (empty override ignored)", cfg.DSN)
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
			content: `dsn = "host=localhost dbname=pathql"`,
			wantMsg: "driver",
		},
		{
			name:    "empty dsn",
			content: `driver = "postgres"`,
			wantMsg: "dsn",
		},
		{
			name: "dsn empty after env expansion",
			content: `
driver = "postgres"
dsn    = "${PATHQL_TOTALLY_UNSET_VAR}"
`,
			wantMsg: "dsn",
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
dsn    = "host=localhost dbname=pathql"

[security]
auth_table_prefix = "1bad"
`,
			wantMsg: "auth_table_prefix",
		},
		{
			name: "auth_table_prefix has invalid char",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[security]
auth_table_prefix = "bad-prefix"
`,
			wantMsg: "auth_table_prefix",
		},
		{
			name: "auth_table_prefix with injection chars",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[security]
auth_table_prefix = "x\"; DROP TABLE"
`,
			wantMsg: "auth_table_prefix",
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
methods        = ["jwt"]
jwt_algorithms = ["HS256"]
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
	// The applied default prefix must itself pass the regex validation.
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
		{"Security.BlockMultipleStatements", cfg.Security.BlockMultipleStatements, true},
		{"Security.MetricsUser", cfg.Security.MetricsUser, "metrics"},
		{"Security.StartupChecks", cfg.Security.StartupChecks, "warn"},
		{"Security.IdentityKind", cfg.Security.IdentityKind, "session_guc"},
		{"Database.ConnMaxIdleTimeMs", cfg.Database.ConnMaxIdleTimeMs, 60000},
		{"Database.MaxTotalBackends", cfg.Database.MaxTotalBackends, 200},
		{"Roles.BaselineRole", cfg.Roles.BaselineRole, "pathql_auth"},
		{"Roles.Prefix", cfg.Roles.Prefix, "pathql_r_"},
		{"Roles.ReaderRole", cfg.Roles.ReaderRole, "pathql_readers"},
		{"Roles.WarmPoolLimit", cfg.Roles.WarmPoolLimit, 64},
		{"Cache.Backend", cfg.Cache.Backend, "embedded"},
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

[security]
block_multiple_statements = false

[limits]
max_concurrent_per_user = 3
max_concurrent_global   = 50
max_requests_per_min_ip = 7

[cache]
backend   = "embedded"
address   = "127.0.0.1:11211"
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
		{"Security.BlockMultipleStatements", cfg.Security.BlockMultipleStatements, false},
		{"Limits.MaxConcurrentPerUser", cfg.Limits.MaxConcurrentPerUser, 3},
		{"Limits.MaxConcurrentGlobal", cfg.Limits.MaxConcurrentGlobal, 50},
		{"Limits.MaxRequestsPerMinIP", cfg.Limits.MaxRequestsPerMinIP, 7},
		{"Cache.Backend", cfg.Cache.Backend, "embedded"},
		{"Cache.Address", cfg.Cache.Address, "127.0.0.1:11211"},
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

func TestLoad_CacheBackendValidation(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"empty defaults to embedded", "", false},
		{"embedded ok", "embedded", false},
		{"memcached rejected", "memcached", true},
		{"unknown rejected", "redis", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := minimalValid
			if tc.backend != "" {
				content += "\n[cache]\nbackend = \"" + tc.backend + "\"\n"
			}
			cfg, err := Load(writeTemp(t, content))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load returned nil error, want error for backend %q", tc.backend)
				}
				if !strings.Contains(err.Error(), "cache backend") {
					t.Errorf("error = %q, want substring %q", err.Error(), "cache backend")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load returned error for backend %q: %v", tc.backend, err)
			}
			if cfg.Cache.Backend != "embedded" {
				t.Errorf("Cache.Backend = %q, want embedded", cfg.Cache.Backend)
			}
		})
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
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "enabled without cert/key",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[tls]
enabled = true
`,
			wantErr: true,
		},
		{
			name: "enabled with cert only",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[tls]
enabled   = true
cert_file = "/etc/pathql/tls.crt"
`,
			wantErr: true,
		},
		{
			name: "enabled with cert and key",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[tls]
enabled   = true
cert_file = "/etc/pathql/tls.crt"
key_file  = "/etc/pathql/tls.key"
`,
			wantErr: false,
		},
		{
			name: "disabled without cert/key ok",
			content: `
driver = "postgres"
dsn    = "host=localhost dbname=pathql"

[tls]
enabled = false
`,
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, tc.content))
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
