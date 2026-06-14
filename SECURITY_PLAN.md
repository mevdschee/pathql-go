# Security plan

This document plans authentication, an `app_user` session variable for row-level
security, and a set of abuse/resource protections for pathql-server. It also
collects a checklist of common API security best practices.

## 1. Current state and threat model

pathql-server today accepts a raw SQL string over `POST /pathql` and runs it.
The key facts that shape this plan:

- There is no authentication. Anyone who can reach the port can run any SQL the
  database role allows.
- The DSN template requires `{username}` and `{password}` with no defaults, so
  the client currently supplies database credentials per request through the
  `variables` field. That client-controlled DSN also lets a caller change
  `host`, so it is an SSRF and credential-injection vector. This must change:
  the server should hold one fixed, least-privilege credential and authenticate
  callers at the application layer instead.
- `pathsqlx.Connect` is called per request and the pool is never closed (leak,
  no connection caps).
- `/metrics` is public and leaks raw query text via `top_queries`.
- Errors return `err.Error()` verbatim (database internals leak to clients).
- No HTTP read/write/idle timeouts, no request body cap, no panic recovery, no
  per-query timeout.

Threat model: the product is "send SQL, get JSON." The real security boundary is
therefore the **database role plus row-level security (RLS)**, not query
parsing. Authentication decides _who_ the caller is; the `app_user` session
variable carries that identity into the database so RLS policies can enforce
_what_ they may see. The HTTP-layer limits below protect availability.

## 2. Goals

1. Authenticate every request using the common methods (API key, JWT, HTTP
   Basic), pluggable so more can be added.
2. Resolve the caller to a user record in a configurable `pathql_auth_`-prefixed
   table, then expose that identity to SQL as a configurable session variable
   (default name discussed below) so RLS can use it.
3. Add resource and abuse protections: per-query timeout, per-user concurrency
   cap, per-IP rate limit, global caps, body-size cap.
4. Close the current information-disclosure and SSRF gaps.

## 3. Part A — Authentication and the `app_user` session variable

### 3.1 Auth tables (`pathql_auth_` prefix, configurable)

A configurable prefix (`AuthTablePrefix`, default `pathql_auth_`) lets an
operator namespace the auth tables. Proposed schema (PostgreSQL):

```sql
-- principals
CREATE TABLE pathql_auth_users (
  id            bigserial PRIMARY KEY,
  username      text NOT NULL UNIQUE,
  password_hash text,                      -- argon2id/bcrypt; null disables Basic
  app_user      text NOT NULL,             -- value pushed into the session variable
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

- The `app_user` column decouples the login identity from the value RLS sees (it
  can be the username, a tenant id, or a database role name). Default it to
  `username`.
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
    AppUser string   // value for the session variable
    UserID  int64
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

### 3.3 Pushing identity into the database (`app_user`)

After authentication, the resolved `AppUser` must be visible to the SQL that
runs, so RLS can read it with `current_setting(...)`. Two correctness
constraints:

- **Same connection.** The variable must be set on the exact connection that
  runs the query. `pathsqlx.PathQuery` calls `db.NamedQuery` against the pool,
  so a `SET` issued on a different pooled connection would not apply.
- **No leakage across requests.** A pooled connection is reused, so a value set
  for one caller must not bleed into the next.

The leak-safe pattern (the same one PostgREST uses) is to run each query inside
a transaction and use `SET LOCAL`, which resets automatically at
COMMIT/ROLLBACK:

```sql
BEGIN;
SET LOCAL "app.user" = $1;          -- the authenticated identity
SET LOCAL statement_timeout = '5000ms';
-- ... the user's query runs here, on this same connection ...
COMMIT;
```

RLS then reads it with `current_setting('app.user', true)`.

PostgreSQL detail worth flagging: a **custom** run-time parameter must be
schema-qualified (contain a dot), e.g. `app.user` or `pathql.user`. A bare
`app_user` raises "unrecognized configuration parameter." The request asked for
`app_user`; I recommend defaulting the configurable name to **`app.user`** for
this reason, and documenting it. The config key (`SessionVariable`) stays
configurable.

This requires running the user query inside the transaction we opened. pathsqlx
does not currently accept a context or transaction. Options, in order of
preference:

- **(Recommended) Extend pathsqlx** with `PathQueryContext(ctx, ...)` and a way
  to run on a caller-supplied `*sqlx.Tx`/`*sql.Conn`. You maintain pathsqlx, so
  this is the clean fix and also unlocks per-query context timeouts (below).
- **Interim, no pathsqlx change:** grab a dedicated `*sql.Conn` from a shared
  pool, `set_config('app.user', $1, false)`, run the query on that conn, then
  reset with `RESET "app.user"` (or `DISCARD ALL`) before returning it to the
  pool. Still needs pathsqlx to run on a given conn; if that is not available,
  the last-resort hack is a per-request pool with `SetMaxOpenConns(1)` so the
  `SET` and the query share the single connection.

Driver note: the above is PostgreSQL, the primary target. Other drivers use
different SQL for the same idea (for example MySQL/MariaDB set a `@app_user`
user-defined variable and cap runtime with
`max_statement_time`/`max_execution_time` rather than `statement_timeout`), so
the session-variable and timeout SQL should be a small per-driver strategy. Keep
PostgreSQL as the first and primary target.

## 4. Part B — Resource and abuse protection

### 4.1 Max runtime per query

- Server side: `context.WithTimeout(req.Context(), MaxQueryDuration)` passed
  into a context-aware query (needs pathsqlx context support).
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
- **Connection pool:** one shared pool with `SetMaxOpenConns` /
  `SetMaxIdleConns` / `SetConnMaxLifetime`, replacing per-request `Connect`.

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

Make the backend configurable (`embedded` vs a Memcached address) so the same
code path serves both the single-instance and clustered deployments.

## 5. Part C — Configuration additions

Extend `config.ini` (TOML supports nested tables; keep the existing flat keys):

```ini
driver = "postgres"
dsn    = "host=localhost port=5432 user=pathql_app password=... dbname=pathql sslmode=require"
listen = ":8000"
verbose = false

[security]
auth_table_prefix = "pathql_auth_"
session_variable  = "app.user"     # dotted name required for a custom Postgres GUC
read_only         = true           # run queries in READ ONLY transactions
trusted_proxies   = ["10.0.0.0/8"] # whose X-Forwarded-For we believe

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
max_result_rows           = 10000

[cache]
backend   = "embedded"        # "embedded" (tqmemory in-process) or "memcached"
address   = ""                # host:port of a shared tqmemory/tqcache when clustered
memory_mb = 64                # embedded tqmemory cap
auth_ttl  = "30s"             # API-key lookup cache TTL
jwks_ttl  = "1h"              # JWKS cache TTL

[timeouts]
read_ms  = 10000
write_ms = 30000
idle_ms  = 60000
```

Secrets (DSN password, JWT HS256 secret) should be loadable from environment
variables, not only the file, and `config.ini` should be `chmod 600`.

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
9. Handler: open a READ ONLY transaction, `SET LOCAL` the session variable and
   `statement_timeout`, run the query, COMMIT, encode JSON.

Make `/metrics` bind to a separate admin listener, since it exposes query text.

## 7. Part E — API security best-practices checklist

A working list of common measures to protect an API, beyond the items above:

- **Transport:** TLS only (1.2+), HSTS, redirect HTTP to HTTPS; optional mTLS.
- **Authentication:** multiple schemes, secrets stored hashed, constant-time
  comparison, short-lived tokens, key rotation, revocation.
- **Authorization:** least privilege. Connect as a restricted DB role; enforce
  per-row access with RLS keyed on the session variable; never the superuser.
- **Read-only by default:** run queries in `READ ONLY` transactions and/or grant
  the app role only `SELECT`, so the "send SQL" surface cannot write or run DDL.
  Make write access an explicit, separate opt-in.
- **Restrict dangerous SQL:** block multiple statements, and at the DB level
  revoke access to `COPY`, `pg_read_file`, `pg_sleep`, large-object and admin
  functions.
- **Rate limiting and throttling:** per IP, per user, and global; `429` with
  `Retry-After`.
- **Concurrency and timeouts:** in-flight caps, HTTP read/write/idle timeouts,
  per-query timeout, graceful shutdown.
- **Input limits:** max body size, max query length, max params, JSON depth.
- **Output hygiene:** generic error messages to clients, full detail only in
  server logs; never echo stack traces or driver errors.
- **Close the DSN injection:** stop accepting client-controlled
  `host`/`username`/ `password`. If per-request DSN variables stay, whitelist
  which variables a client may set and forbid connection-target fields.
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
- **Dependency hygiene:** update old deps (gorilla/mux 1.7.3, sqlx 1.2.0 are
  dated) and run vulnerability scanning in CI.
- **Fail closed:** deny when auth or limits are misconfigured rather than
  allowing.
- **Health/metrics isolation:** protect or separate operational endpoints.

## 8. Suggested phasing

1. Foundation and quick wins: shared pool with caps, HTTP timeouts, body cap,
   panic recovery, generic errors, lock down DSN variables, gate `/metrics`.
2. Authentication core: `Authenticator` interface, API key + Basic against the
   `pathql_auth_` tables, `Principal` on context.
3. Session variable: extend pathsqlx for context/transaction, READ ONLY
   transaction with `SET LOCAL`, example RLS policy and docs.
4. JWT/OIDC: signature verification, JWKS caching, claim mapping.
5. Abuse protection: wire in the `tqmemory` cache (4.5), per-IP rate limit,
   per-user and global concurrency, `Retry-After`, metrics for limits and auth
   failures.

## 9. Open decisions

- PostgreSQL only first, or MySQL/others in parallel? (RLS and the SET syntax
  differ.)
- Session variable name: default to `app.user` (dotted, required by Postgres)
  while keeping it configurable, or insist on the literal `app_user`?
- Extend pathsqlx for context/transaction support (recommended), or use the
  single-connection interim approach?
- JWT: trust verified tokens, or always require a matching enabled user row?
- Cache backend: ship with embedded `tqmemory` only for now, or add the shared
  `tqmemory`/`tqcache` sidecar mode up front for multi-instance deployments?
