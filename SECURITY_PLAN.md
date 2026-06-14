# Security plan

This document covers authentication, the two identity models, the per-role
connection model for row-level security, and the abuse/resource protections for
pathql-server, plus a checklist of common API security best practices.

## 1. Threat model

The product is "send SQL, get JSON." There are two identity models, selected by
`[security] identity_kind`:

- **`none`** (default): a single shared database connection, no row-level
  security. Every authenticated caller runs as the same database role, so the
  only boundary is the role's own grants (read-only `SELECT`). This is the
  development / single-tenant on-ramp; there is no per-caller isolation, so do
  not use it to separate tenants.
- **`login_role`**: the real multi-tenant boundary is the **database role plus
  row-level security (RLS)**, not query parsing. Authentication decides _who_ the
  caller is; the server then connects as that caller's own database role so RLS
  policies can enforce _what_ they may see.

The HTTP-layer limits below protect availability in both models.

## 2. Goals

1. Authenticate every request using the common methods (API key, JWT, HTTP
   Basic), pluggable so more can be added. (In `none` mode authentication is
   optional; in `login_role` mode it is required, since a principal is needed to
   pick the role.)
2. Resolve the caller to a user record in a configurable `pathql_auth_`-prefixed
   table. In `login_role` mode, connect as the caller's own database role so RLS
   can read `current_user`.
3. Add resource and abuse protections: per-query timeout, per-user concurrency
   cap, per-IP rate limit, global caps, body-size cap.

## 3. Part A — Authentication and identity

### 3.1 Auth tables (`pathql_auth_` prefix, configurable)

A configurable prefix (`AuthTablePrefix`, default `pathql_auth_`) lets an
operator namespace the auth tables. Schema (PostgreSQL):

```sql
-- principals
CREATE TABLE pathql_auth_users (
  id            bigserial PRIMARY KEY,
  username      text NOT NULL UNIQUE,
  password_hash text,                      -- argon2id/bcrypt; null disables Basic
  app_user      text NOT NULL,             -- application principal name (audit, metrics, limits)
  enabled       boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- API keys (store only a hash, never the raw key)
CREATE TABLE pathql_auth_api_keys (
  id          bigserial PRIMARY KEY,
  user_id     bigint NOT NULL REFERENCES pathql_auth_users(id),
  key_prefix  text NOT NULL,               -- first chars, for lookup + display
  key_hash    bytea NOT NULL,              -- sha-256 of the full key
  name        text,
  expires_at  timestamptz,
  enabled     boolean NOT NULL DEFAULT true,
  last_used_at timestamptz,
  UNIQUE (key_prefix)
);
```

Notes:

- The `app_user` column is the application principal name, used for audit logs,
  the per-user concurrency cap, and metrics; the user row's id maps to its
  database login role, which is what RLS keys on via `current_user`. Default
  `app_user` to `username`.
- API keys and passwords are never stored in clear text. API keys: store
  `sha-256(key)`; look up by a non-secret prefix, then compare the hash in
  constant time. Passwords: argon2id (preferred) or bcrypt.
- JWT does not need a row by default. Two modes (configurable): trust a verified
  token and map a claim straight to `app_user`, or additionally require a
  matching enabled row in `pathql_auth_users` (recommended for revocation).

### 3.2 Supported methods (pluggable `Authenticator` interface)

Define an interface so methods are independent and the enabled set is
configurable:

```go
type Principal struct {
    AppUser string   // application principal name (audit, metrics, limits)
    UserID  int64    // maps to the caller's database role
    Scopes  []string
}

type Authenticator interface {
    // Authenticate returns a Principal, or ErrNoCredentials if this method does
    // not apply to the request (so the chain can try the next method).
    Authenticate(r *http.Request) (*Principal, error)
}
```

Initial implementations, in match order:

1. **API key** — `Authorization: ApiKey <key>` or a configurable header
   (`X-API-Key`). Hash, look up by prefix, constant-time compare, check
   `enabled` and `expires_at`, touch `last_used_at` (best-effort, async). Cache
   the verified key-hash -> principal mapping in `tqmemory` with a short TTL
   (see 4.5) so a busy key does not hit the database on every request;
   revocation lag is bounded by the TTL.
2. **JWT bearer** — `Authorization: Bearer <jwt>`. Verify signature, then `exp`,
   `nbf`, `iss`, `aud`. Support HS256 (shared secret) and RS256/ES256 via a
   static public key or a JWKS URL. Cache the JWKS in `tqmemory` keyed by `kid`
   (see 4.5); its stale/thundering-herd support means one fetch refreshes the
   key on rotation while other requests keep serving the cached key. Map a
   configurable claim (`sub` by default) to `app_user`. This covers OAuth2/OIDC
   access tokens.
3. **HTTP Basic** — `Authorization: Basic <base64>`. Look up the user, verify
   the password hash in constant time. Gate behind TLS only.

Future methods slot into the same interface: opaque session cookies, mTLS client
certificates (`r.TLS.PeerCertificates`), HMAC request signing with a nonce and
timestamp window for replay protection, and OAuth2 token introspection (RFC
7662).

Resolution rules:

- Try each enabled authenticator; first success wins.
- On total failure return `401` with a generic body and a `WWW-Authenticate`
  header. Do not reveal which field was wrong (avoid user enumeration). Keep
  timing roughly constant.
- Count auth failures as a metric; apply backoff/lockout on repeated failures
  from the same key or IP (brute-force protection).
- Fail closed: if auth is enabled but misconfigured, deny.

### 3.3 Pushing identity into the database (`current_user`)

This section applies to `login_role` mode. (In the default `none` mode the
server runs every query on one shared connection and binds no per-caller
identity, so there is no RLS isolation; the rest of this section does not apply.)

After authentication, the resolved principal must reach the SQL that runs so RLS
can isolate rows. The server connects to PostgreSQL **as the caller's own
database role** and lets RLS read `current_user`.

- A user with id N maps to the managed login role `<prefix>N` (default prefix
  `pathql_r_`). The server keeps a per-role connection pool, authenticating each
  connection with a password derived as `HMAC(roles.password_secret, role)`.
- The query runs inside a read-only transaction on that connection, with a
  transaction-local `statement_timeout` (plus
  `idle_in_transaction_session_timeout` and an optional `work_mem`) set via
  `set_config(name, value, true)`, the bound-parameter form of `SET LOCAL`.
- RLS policies read `current_user`. Because the connected role is fixed at
  authentication and the role system enforces membership, a query cannot forge
  another identity, even inside a single statement (no CTE or `set_config` can
  change `current_user`). The identity boundary lives in the database, not in
  anything the request can set.

The server never creates roles and never holds `CREATEROLE`.
`GET /admin/roles/sync` emits the exact `CREATE ROLE` / `GRANT` / `DROP ROLE` DDL
to make the database roles match the users table; an operator or cron applies it.
See ROLE_MANAGEMENT_PLAN.md for the design.

Driver note: this is PostgreSQL, the primary target. The role / `current_user`
mechanism is Postgres-specific and has no portable equivalent, so the per-role
identity model targets PostgreSQL only.

## 4. Part B — Resource and abuse protection

### 4.1 Max runtime per query

- Server side: `context.WithTimeout(req.Context(), MaxQueryDuration)` passed
  into the context-aware query.
- Database side (defense in depth): `SET LOCAL statement_timeout` in the same
  transaction (PostgreSQL) so the database also kills a runaway query even if
  the Go side is blocked. Return `503`/`504` with a generic message on timeout.

### 4.2 Max concurrent requests per user

- A counting semaphore keyed by `AppUser` (map of user to a buffered channel or
  an atomic counter with a cap). Acquire after authentication, release in a
  `defer`.
- Over the cap returns `429` (or `503`) with `Retry-After`. Also keep a
  **global** in-flight cap to bound total load.

### 4.3 Max requests per minute per IP

- Fixed-window counter keyed by `ratelimit:<ip>:<minute-bucket>` using
  `tqmemory.Increment(key, 1)` with a TTL equal to the window (see 4.5). The
  first increment seeds the counter; over the configured count the request is
  rejected. `Increment` returns the new value atomically, so this works
  correctly under concurrency without a separate lock, and the TTL evicts old
  windows so memory stays bounded without a manual cleanup goroutine.
- Derive the client IP correctly: only trust `X-Forwarded-For`/`X-Real-IP` when
  the request comes from a configured trusted proxy/CIDR, otherwise use
  `RemoteAddr`. Otherwise an attacker spoofs the header to dodge the limit.
- Over the limit returns `429` with `Retry-After`.
- Use the same `Increment` + TTL pattern for brute-force lockout, keyed by API
  key prefix or username, incremented on each auth failure.

### 4.4 Other limits

- **Body size:** wrap the body in `http.MaxBytesReader` (e.g. 1 MiB) and bound
  query length and parameter count.
- **Result size:** cap rows/bytes returned, or force a `LIMIT`, to stop a single
  query from exhausting memory.
- **Proactive cost ceiling:** before running a query, `EXPLAIN (FORMAT JSON)` it
  (no execution) and reject it with `400` when the planner's estimated total cost
  or output rows exceed `limits.max_estimated_cost` / `max_estimated_rows`. This
  stops an accidental sequential scan over a huge table or a cross join before it
  ties up a connection, rather than relying on `statement_timeout` to kill it
  after the work has started. PostgreSQL only; the estimate is logged, not
  returned. 0 disables.
- **Connection pool:** in `none` mode a single shared pool; in `login_role` mode
  one pool per database role, each with `SetMaxOpenConns` / `SetMaxIdleConns` /
  `SetConnMaxLifetime`, plus a global semaphore (`max_total_backends`) capping
  connections across all pools. Pool sizing is config-only (no runtime tuning).

### 4.5 Caching layer (tqmemory / tqcache)

Several features above need a small key/value cache: per-IP rate-limit counters,
brute-force counters, the JWKS cache, and the API-key lookup cache. Use your own
caches rather than adding a new dependency family:

- **`tqmemory` embedded in-process (default).** Construct once at startup with
  `tqmemory.NewSharded(cfg, workers)` and share it. Relevant calls:
  `Increment(key, delta)` for atomic fixed-window counters, `Set(key, val, ttl)`
  / `Get(key)` for the JWKS and auth-lookup caches, and the
  stale/thundering-herd behaviour (hard TTL = TTL * stale multiplier) so a
  single request refreshes an expired JWKS entry while the rest keep serving the
  cached one. No network hop, no extra process.
- **`tqmemory` or `tqcache` as a sidecar (scale-out).** When more than one
  pathql-server instance runs behind a load balancer, in-process counters drift
  per instance. Point all instances at a shared `tqmemory` (volatile) or
  `tqcache` (disk-persistent) over the Memcached protocol so rate limits and
  lockouts are global. Pick `tqcache` when the state must survive a restart, for
  example opaque server-side sessions if a cookie/session authenticator is added
  later.

The shipped implementation is the embedded in-process cache only; there is no
configurable backend. A shared/Memcached-backed cache for clustered deployments
remains a possible future addition, but until it exists the config exposes no
backend toggle (one fewer knob to misconfigure).

## 5. Part C — Configuration additions

Extend `config.ini` (TOML supports nested tables; keep the existing flat keys):

```ini
driver = "postgres"
dsn    = "host=localhost port=5432 dbname=pathql sslmode=require" # shared pool, identity_kind = "none"
listen = ":8000"
verbose = false

[security]
identity_kind     = "none"         # "none" (shared dsn, no RLS) or "login_role"
auth_table_prefix = "pathql_auth_"
read_only         = true           # run queries in READ ONLY transactions
trusted_proxies   = ["10.0.0.0/8"] # whose X-Forwarded-For we believe

# [roles] is used only when identity_kind = "login_role".
[roles]
base_dsn        = "host=localhost port=5432 dbname=pathql sslmode=require" # no user=
baseline_role   = "pathql_auth"    # role for pre-auth auth-table lookups
prefix          = "pathql_r_"      # user id N -> role pathql_r_N
reader_role     = "pathql_readers" # group granting read access
password_secret = "${PATHQL_ROLE_SECRET}" # derives each role's connection password

[auth]
methods        = ["apikey", "jwt", "basic"]
api_key_header = "X-API-Key"
jwt_algorithms = ["RS256"]
jwt_jwks_url   = "https://issuer/.well-known/jwks.json"
jwt_issuer     = "https://issuer/"
jwt_audience   = "pathql"
jwt_user_claim = "sub"
require_user_row = true            # JWT subject must match an enabled user row

[limits]
max_query_ms              = 5000
max_concurrent_per_user   = 10
max_concurrent_global     = 200
max_requests_per_min_ip   = 120
max_body_bytes            = 1048576
max_response_bytes        = 10485760  # cap the encoded JSON response; 413 over it

[cache]
memory_mb = 64                # embedded in-process cache cap
auth_ttl  = "30s"             # API-key lookup cache TTL
jwks_ttl  = "1h"              # JWKS cache TTL

[timeouts]
read_ms  = 10000
write_ms = 30000
idle_ms  = 60000
```

Secrets (`dsn`, `roles.base_dsn`, `roles.password_secret`, the JWT HS256 secret)
should be loadable from environment variables, not only the file, and
`config.ini` should be `chmod 600`. The `dsn` also accepts a `PATHQL_DSN`
environment override.

## 6. Part D — Request lifecycle (middleware chain)

Order matters: reject cheaply before doing expensive work.

1. Panic recovery (one bad request must not crash the server).
2. Request ID + structured logging (redact secrets).
3. Body size limit.
4. Global in-flight limiter.
5. Per-IP rate limiter.
6. Authentication -> `Principal` on the request context.
7. Per-user concurrency limiter.
8. Per-query timeout context.
9. Handler: pick the connection by identity model (`none` uses the shared pool;
   `login_role` acquires the caller's per-role connection), open a READ ONLY
   transaction, `SET LOCAL` the `statement_timeout` (and other limits), run the
   query, COMMIT, encode JSON.

`/metrics` exposes query text, so it is served on the main listener but
authorized only to the configured `metrics_user` principal (which is refused on
`/pathql`); an empty `metrics_user` disables it (fail closed).

## 7. Part E — API security best-practices checklist

A working list of common measures to protect an API, beyond the items above:

- **Transport:** TLS only (1.2+), HSTS, redirect HTTP to HTTPS; optional mTLS.
- **Authentication:** multiple schemes, secrets stored hashed, constant-time
  comparison, short-lived tokens, key rotation, revocation.
- **Authorization:** least privilege. Connect as the caller's own restricted DB
  role; enforce per-row access with RLS keyed on `current_user`; never the
  superuser. Never take connection-target fields (`host`/`user`/`password`) from
  the request.
- **Read-only by default:** run queries in `READ ONLY` transactions and/or grant
  the app role only `SELECT`, so the "send SQL" surface cannot write or run DDL.
  Make write access an explicit, separate opt-in.
- **Restrict dangerous SQL:** at the DB level revoke access to `COPY`,
  `pg_read_file`, `pg_sleep`, large-object and admin functions. As defense in
  depth above the DB, the optional **SQL gate** (`[security] sql_gate = "on"`,
  `internal/sqlgate`) rejects, before execution, anything that is not a single
  read-only statement over non-catalog objects: stacked statements,
  non-`SELECT`/`WITH`/`TABLE`/`VALUES` statements (`SET`, `SHOW`, `EXPLAIN`,
  `COPY`, `CALL`, `DO`, DDL/DML), and any reference to `pg_*` or
  `information_schema` (catalog enumeration RLS does not cover). It is a string
  setting so stricter modes (table/column allowlists, forced `LIMIT`, a
  planner-cost ceiling) can follow.
- **Rate limiting and throttling:** per IP, per user, and global; `429` with
  `Retry-After`.
- **Concurrency and timeouts:** in-flight caps, HTTP read/write/idle timeouts,
  per-query timeout, graceful shutdown.
- **Input limits:** max body size, max query length, max params, JSON depth.
- **Output hygiene:** generic error messages to clients, full detail only in
  server logs; never echo stack traces or driver errors.
- **CORS:** explicit allowed origins, never `*` together with credentials.
- **Security headers:** `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store` on sensitive responses, restrictive `Content-Type`
  checks on input.
- **Brute-force / enumeration:** lockout and backoff on repeated auth failures;
  uniform error responses and timing.
- **Replay protection:** for signed requests, nonce + timestamp window.
- **Auditing and monitoring:** log auth outcomes with the principal, alert on
  auth failure spikes and rate-limit hits; the existing metrics endpoint already
  gives a base to build on.
- **Secrets management:** load credentials from env/secret store, restrict file
  permissions, keep secrets out of logs and out of the metrics endpoint.
- **Dependency hygiene:** keep dependencies current and run vulnerability
  scanning in CI.
- **Fail closed:** deny when auth or limits are misconfigured rather than
  allowing.
- **Health/metrics isolation:** protect or separate operational endpoints.
