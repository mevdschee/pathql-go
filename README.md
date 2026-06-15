# pathql-server

PathQL server implementation in Go (see: [PathQL.org](https://pathql.org/)).

PathQL lets you write SQL queries that automatically produce nested JSON from
flat SQL result rows. The nesting structure is inferred from table aliases and
foreign key metadata, with optional path hints for overrides.

## How it works

You send a POST request to `/pathql` with a JSON body containing a SQL query and
optional parameters. The [pathsqlx](https://github.com/mevdschee/pathsqlx)
engine automatically determines the JSON structure by:

1. **Parsing the query** to identify tables, aliases, and joins.
2. **Detecting cardinality** using foreign key metadata (one-to-many vs
   many-to-one).
3. **Generating JSON paths** for each column based on the query structure.

If automatic inference isn't sufficient, you can use **PATH hints** to override
the structure.

### PATH hints

PATH hints override the automatic path inference for table aliases. Provide
hints using the `paths` parameter in the request body:

```json
{
  "query": "SELECT ...",
  "params": {},
  "paths": { "alias": "$.path" }
}
```

PATH hint format:

- **`alias`**: the table alias (or `$` for queries without a real table)
- **`$.path`**: the JSON path for that table's columns
- If the path ends with `[]`, it's an array; otherwise, it's an object
- `$` alone means the root is a single object

## Quick start

The simplest setup is one shared database connection and no row-level security,
which is the default. Point `dsn` at your database:

```ini
# config.ini
driver = "postgres"
dsn    = "host=localhost port=5432 dbname=pathql sslmode=disable"
listen = ":8000"
```

Build and run, then send a query:

```sh
go build -o pathql-server
./pathql-server

curl -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT id, content FROM posts WHERE id = :id","params":{"id":1}}'
# [{ "id": 1, "content": "blog started" }]
```

That is the whole product: send SQL, get nested JSON (see [Examples](#examples)).
Everything below is optional hardening you add as you need it: authentication,
abuse limits, TLS, and per-user row-level security.

There are two identity models, selected by `[security] identity_kind`:

- **`none`** (default): a single shared connection. There is no per-caller
  isolation, so every authenticated caller runs as the same database role. This
  is the development / single-tenant on-ramp shown above.
- **`login_role`**: the server connects as the caller's own per-user database
  role and PostgreSQL row-level security keys on `current_user`, an unforgeable
  identity. This is how multi-tenant isolation is enforced; it needs per-role
  provisioning (see [Row-level security](#row-level-security)).

Each model has a one-command Docker demo: [examples/demo](examples/demo/) for the
simple shared-connection mode, and [examples/login-role](examples/login-role/)
for per-user row-level security.

## Configuration

Create a `config.ini` file in the project root. It is TOML. The minimal file
above is enough to start; the full set of options is:

```ini
driver  = "postgres"
dsn     = "host=localhost port=5432 dbname=pathql sslmode=disable"  # identity_kind = "none"
listen  = ":8000"
verbose = false

[database]
max_open_conns       = 50
max_idle_conns       = 10
conn_max_lifetime_ms = 300000

[security]
identity_kind               = "none"   # "none" (shared dsn, no RLS) or "login_role"
auth_table_prefix           = "pathql_auth_"
read_only                   = true
metrics_user                = "metrics"
startup_checks              = "warn"
sql_gate                    = "off"    # "off" or "on" (see SQL gate)
xsrf                        = "off"    # "off" or "on" (see XSRF / CSRF protection)
writes                      = "off"    # "off" or "on" (see Writes)
# admin_user                = "admin"
# trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
# allow_ips = ["10.0.0.0/8"]           # IP firewall allowlist (see IP firewall)
# deny_ips  = ["203.0.113.7"]          # IP firewall denylist

[auth]
methods        = ["apikey", "basic"]
api_key_header = "X-API-Key"

# [roles] is used only when identity_kind = "login_role". Omit it for the shared
# "none" mode (which uses the top-level dsn instead).
[roles]
base_dsn        = "host=localhost port=5432 dbname=pathql sslmode=disable"  # no user=
baseline_role   = "pathql_auth"
prefix          = "pathql_r_"
reader_role     = "pathql_readers"
password_secret = "${PATHQL_ROLE_SECRET}"

[limits]
max_query_ms              = 5000
max_body_bytes            = 1048576
max_response_bytes        = 10485760
max_concurrent_per_user   = 10
max_concurrent_global     = 200
max_requests_per_min_ip   = 120
max_auth_failures_per_min = 60
work_mem_kb               = 0
max_estimated_cost        = 0          # EXPLAIN cost ceiling; 0 disables (Postgres only)
max_estimated_rows        = 0          # EXPLAIN estimated-rows ceiling; 0 disables
max_affected_rows         = 0          # write blast-radius cap; 0 disables (see Writes)

[timeouts]
read_ms  = 10000
write_ms = 30000
idle_ms  = 60000

[cache]
memory_mb = 64
auth_ttl  = "30s"
jwks_ttl  = "1h"

[tls]
enabled = false
hsts    = true
# cert_file     = "/etc/pathql/tls.crt"
# key_file      = "/etc/pathql/tls.key"
# redirect_http = ":8080"

[cors]
allowed_origins = []
```

Top-level options:

- **`driver`**: database driver (e.g. `"postgres"`).
- **`dsn`**: the shared connection string used when `identity_kind = "none"`
  (the default). Required in that mode; ignored in `login_role` mode, which uses
  `[roles] base_dsn` instead. Supports `${ENV}` expansion, and the `PATHQL_DSN`
  environment variable overrides it verbatim.
- **`listen`**: listen address serving `POST /pathql` and `GET /metrics`
  (default `:8000`).
- **`verbose`**: verbose logging (default `false`). When enabled, logs
  timestamp, status code, response size, and latency for each request.

Section options:

- **`[database]`**: connection-pool caps. In `login_role` mode they apply to each
  per-role pool (`max_open_conns`, `max_idle_conns`, `conn_max_lifetime_ms`),
  plus `max_total_backends`, the hard ceiling on connections across all pools.
- **`[security]`**: `identity_kind` selects the connection/identity model:
  `"none"` (default, single shared `dsn`, no RLS) or `"login_role"` (per-role
  connections with `current_user` RLS, see
  [Row-level security](#row-level-security)). `auth_table_prefix` namespaces the
  auth tables. `metrics_user` is the principal allowed to read `/metrics` (see
  [Metrics](#metrics)). `admin_user` gates the [admin routes](#admin-routes).
  `startup_checks` controls the [startup hardening check](#startup-hardening-checks).
  `sql_gate` enables the optional pre-execution [SQL gate](#sql-gate).
  `xsrf` enables the optional [XSRF / CSRF protection](#xsrf--csrf-protection).
  `writes` enables optional [write support](#writes) (off by default).
  `trusted_proxies` is a list of CIDRs (or bare IPs) whose `RemoteAddr` is
  trusted to set `X-Forwarded-For` / `X-Real-IP`; the rate limiter (and the IP
  firewall) use it to find the real client IP. `allow_ips` and `deny_ips` are the
  optional [IP firewall](#ip-firewall) lists.
- **`[auth]`**: see [Authentication](#authentication).
- **`[roles]`**: the per-role connection model, used only when
  `identity_kind = "login_role"`, see [Row-level security](#row-level-security).
  `base_dsn` is the user-less connection string the server appends `user=<role>`
  and a derived password to; `baseline_role` is the role used for auth lookups;
  `prefix` derives a user's role name from its id; `reader_role` is the group
  granting read access; and `password_secret` derives each role's password.
- **`[limits]`**: `max_body_bytes` caps the request body and `max_response_bytes`
  caps the encoded response (an oversized result is rejected with `413`).
  `max_query_ms` bounds each query (a Go-side request timeout plus a Postgres
  `statement_timeout`, `idle_in_transaction_session_timeout`, and an optional
  `work_mem_kb`). `max_concurrent_per_user`, `max_concurrent_global`,
  `max_requests_per_min_ip` and `max_auth_failures_per_min` are the
  abuse-protection caps, see
  [Rate limiting and concurrency](#rate-limiting-and-concurrency).
  `max_estimated_cost` and `max_estimated_rows` are the proactive
  [cost ceiling](#cost-ceiling). `max_affected_rows` is the write blast-radius
  cap (see [Writes](#writes)).
- **`[timeouts]`**: HTTP server `read_ms`, `write_ms`, and `idle_ms`.
- **`[cache]`**: the in-process counter/JWKS cache, see [Cache](#cache).
- **`[tls]`**: optional TLS termination, see [TLS](#tls).
- **`[cors]`**: `allowed_origins` is an explicit list of origins for browser
  cross-origin access, see [CORS](#cors).

### Secrets

Secrets should not live in the file in clear text. `roles.base_dsn`,
`roles.password_secret` and `auth.jwt_hs256_secret` support `${ENV}` expansion,
so put the value in an environment variable and reference it, for example
`password_secret = "${PATHQL_ROLE_SECRET}"`. Tokens that are not set expand to
the empty string. Keep `config.ini` readable only by the server user
(`chmod 600`).

## Authentication

Authentication is configured in the `[auth]` section. `methods` is an ordered
list; each request is tried against each method until one succeeds. Supported
methods are `"apikey"`, `"basic"`, and `"jwt"`. Leaving `methods` empty disables
authentication entirely (allowed only in `identity_kind = "none"` mode, since
`login_role` needs a principal to pick a role); the server logs a clear warning
at startup when it does.

- **`apikey`**: presented as `Authorization: ApiKey <key>` or in the header
  named by `api_key_header` (default `X-API-Key`). The server stores only a
  SHA-256 hash of the key and looks it up by a non-secret prefix.
- **`basic`**: standard HTTP Basic; the password is verified against a bcrypt
  hash. Use it only over TLS.
- **`jwt`**: a bearer token presented as `Authorization: Bearer <jwt>`, see
  [JWT](#jwt).

Failed authentication returns `401` with a generic body and a
`WWW-Authenticate` header. The response never reveals which field was wrong.

Once a request authenticates, the resolved `app_user` is the principal name used
for audit logging, metrics, per-user rate limiting, and the `metrics_user` /
`admin_user` route checks. It is not the row-level-security identity: in
`login_role` mode RLS keys on the caller's own database role (`current_user`),
which is derived from the user id, not from `app_user`. See
[Row-level security](#row-level-security).

### JWT

`jwt` is not enabled by default. Add `"jwt"` to `methods` and configure the
`jwt_*` keys under `[auth]`:

```ini
[auth]
methods          = ["jwt"]
jwt_algorithms   = ["RS256"]
jwt_jwks_url     = "https://issuer.example/.well-known/jwks.json"
jwt_issuer       = "https://issuer.example/"
jwt_audience     = "pathql"
jwt_user_claim   = "sub"
require_user_row = false
# For HS256 instead of RS256/ES256:
# jwt_algorithms   = ["HS256"]
# jwt_hs256_secret = "${JWT_HS256_SECRET}"
```

- **`jwt_algorithms`**: the accepted signing algorithms; must be non-empty. The
  parser rejects any token whose `alg` is not in this list, which is the primary
  defense against algorithm-confusion attacks. The unsecured `none` algorithm is
  never accepted.
- **`jwt_hs256_secret`**: the shared secret for `HS256`. Required when an HMAC
  algorithm is configured. It is `${ENV}`-expandable, keep it out of the file.
- **`jwt_jwks_url`**: the JWKS endpoint for asymmetric algorithms (`RS256`,
  `ES256`, and so on). Required for those. The server fetches the key set,
  selects the key by the token `kid`, and caches the document for `jwks_ttl`
  (see [Cache](#cache)).
- **`jwt_issuer`** / **`jwt_audience`**: when set, the token `iss` / `aud` must
  match. Leave empty to skip the check.
- **`jwt_user_claim`**: the claim mapped to the `app_user` identity (default
  `sub`).
- **`require_user_row`**: when true, the claim value must match an enabled row in
  the users table; the row's `app_user` is then used. When false, the claim value
  is used directly.

### Auth tables

The authenticators read two tables, `<prefix>users` and `<prefix>api_keys`,
where `<prefix>` is `auth_table_prefix` (default `pathql_auth_`). The PostgreSQL
schema, plus notes on how to insert a user and an API key (store `sha-256(key)`
as `key_hash` and the first 8 characters as `key_prefix`), is in
[internal/auth/schema.sql](internal/auth/schema.sql). Apply it to your database
before enabling auth:

```sh
psql "$DATABASE_URL" -f internal/auth/schema.sql
```

## Row-level security

Row-level security is the hardened, multi-tenant mode, enabled with
`[security] identity_kind = "login_role"`. The default `none` mode has **no**
row-level security: every caller runs on one shared connection as the same
database role, so use it only for development or a single trusted tenant.

In `login_role` mode the server connects to PostgreSQL **as the caller's own
database role** and runs the query inside a read-only transaction (when
`read_only = true`) on that connection. A `statement_timeout` matching
`max_query_ms` (plus an `idle_in_transaction_session_timeout` and an optional
`work_mem`) is set transaction-locally via `set_config(name, value, true)`.

Your row-level-security policies read the identity with `current_user`. Because
the role is fixed by authentication and the PostgreSQL role system enforces
membership, a query cannot forge another identity, even in a single statement
(no CTE or function can change `current_user`). This is an unforgeable
tenant-isolation boundary. A runnable example, including the policy, the
`ENABLE ROW LEVEL SECURITY` statements, and the least-privilege grants, is in
[examples/rls_policy.sql](examples/rls_policy.sql). See
[examples/login-role](examples/login-role/) for a full runnable setup and
[ROLE_MANAGEMENT_PLAN.md](ROLE_MANAGEMENT_PLAN.md) for the design.

### Role configuration

The per-role model is configured under `[roles]` and needs at least one auth
method (it needs a principal to pick the role):

- **`base_dsn`**: the connection string **without** a user; the server appends
  `user=<role>` and the role's derived password per connection.
- **`baseline_role`**: the role used for pre-auth work (reading the auth tables)
  before the caller is known. Default `pathql_auth`.
- **`prefix`**: a user with id N maps to the login role `<prefix>N`
  (default `pathql_r_`); the role name is derived from the id.
- **`reader_role`**: a group role granting read access that every managed role is
  a member of (default `pathql_readers`). Managed roles are never members of each
  other.
- **`password_secret`** (required): the master secret each per-role connection
  password is derived from as `HMAC(password_secret, role)`. The same derivation
  goes into the sync DDL (`CREATE ROLE ... PASSWORD`) and is re-derived at connect
  time, so no per-role secret is stored. The `baseline_role` must have that
  derived password set too. Pair it with `scram-sha-256` in `pg_hba.conf` for
  production. `${ENV}`-expandable; keep it out of the file.
- **`[database] max_total_backends`** caps total connections across all per-role
  pools (a shared semaphore); **`warm_pool_limit`** bounds how many pools keep
  idle connections. Both are config only.

  Client-cert + `pg_ident` is intentionally not used for per-role auth: with one
  server cert it would require enumerating a `pg_ident` line per role and
  reloading on every role creation, which does not fit dynamically managed roles.

The server never runs role DDL and never holds `CREATEROLE`. `GET /admin/roles/sync`
emits the exact `CREATE ROLE` / `GRANT` / `DROP ROLE` statements needed to make
the database roles match the users table; an operator or cron job applies them.

## Admin routes

When `[security] admin_user` is set, the server serves `/admin/*` on the main
listener, authorized only for that principal (which may do nothing else: it is
refused on `/pathql` and `/metrics`). An empty `admin_user` disables the routes
(fail closed). Admin requests authenticate like any other, are rate-limited, and
are audit-logged.

- **`POST /admin/users`** `{username, app_user?, password?, generate_api_key?}`:
  creates a user (optionally with a bcrypt password for Basic and a freshly
  generated API key, returned once) and reports the managed role name the next
  sync will create.
- **`DELETE /admin/users/{id}`**: removes the user and its API keys and evicts the
  role's pool; the role is dropped by the next sync.
- **`GET /admin/roles/sync`**: returns the role-sync DDL (`create`, `grant_reader`,
  `drop`, and the ordered `ddl`) for a cron job to apply. login_role only.

Connection-pool sizing is set in `[database]` config, not at runtime.

## Rate limiting and concurrency

Three abuse-protection caps run on the public listener, all configured under
`[limits]`:

- **`max_requests_per_min_ip`**: a fixed-window per-IP rate limit. Over the
  budget returns `429` with a `Retry-After` header. The client IP is taken from
  `RemoteAddr`, or from `X-Forwarded-For` / `X-Real-IP` only when `RemoteAddr` is
  one of the `trusted_proxies` CIDRs, so a spoofed header from an untrusted peer
  is ignored.
- **`max_concurrent_global`**: caps the total number of in-flight requests. Over
  the cap returns `503` with `Retry-After` rather than queueing.
- **`max_concurrent_per_user`**: caps in-flight requests per authenticated
  `app_user`. Over the cap returns `429`. Unauthenticated requests are not
  per-user limited (the limiter runs after authentication, so the key is the
  resolved identity).
- **`max_auth_failures_per_min`**: a fixed-window brute-force lockout. After this
  many authentication failures in a minute for the same credential, further
  attempts are rejected with `429` and a `Retry-After` until the window rolls
  over. The counter is keyed by the credential being presented (API-key prefix or
  HTTP Basic username), falling back to the client IP, so one bad key or username
  is throttled regardless of source IP. Bearer tokens fall back to the IP key.

Set any cap to `0` to disable it. The per-IP limiter and the lockout counter use
the cache (see below).

## Cache

The `[cache]` section configures a small in-process cache used for the rate-limit
counters and for caching fetched JWKS documents. It is bounded to `memory_mb`
MiB. `auth_ttl` and `jwks_ttl` are
duration strings (e.g. `"30s"`, `"1h"`); `jwks_ttl` is how long a fetched JWKS
document is reused before refetching.

## TLS

TLS termination is optional and off by default. To enable it, set
`[tls] enabled = true` and provide `cert_file` and `key_file`. The public
listener then serves HTTPS and adds an HSTS header (controlled by `hsts`, on by
default). Set `redirect_http` to an address (for example `":8080"`) to run a
small extra listener that `301`-redirects plain HTTP to the HTTPS URL.

Terminating TLS at a reverse proxy or load balancer instead is also fine; in that
case leave TLS disabled here and set `trusted_proxies` so the rate limiter reads
the forwarded client IP.

## CORS

`[cors] allowed_origins` is an explicit list of origins permitted for browser
cross-origin requests. A matching `Origin` is echoed back in
`Access-Control-Allow-Origin`; a preflight `OPTIONS` is answered with `204`. The
wildcard `*` is never emitted, so the response is always safe to combine with
credentials. An empty list disables cross-origin access.

## IP firewall

An optional allow/deny IP firewall gates **every** route (`/pathql`, `/schema`,
`/health`, `/metrics`, `/admin/*`) by the resolved client IP, before
authentication. It is configured under `[security]`:

- **`deny_ips`**: a list of CIDRs (or bare IPs). A request from any address in
  the list is rejected with `403`.
- **`allow_ips`**: a list of CIDRs (or bare IPs). When non-empty, only addresses
  in the list are admitted and everything else gets `403` (default-deny). An
  empty list admits all addresses (still subject to `deny_ips`).

`deny_ips` is evaluated first, so an address in both lists is denied. Leaving both
empty disables the firewall. The client IP is resolved with the same
`trusted_proxies` rules the rate limiter uses, so an untrusted peer cannot lift
itself onto the allowlist with a spoofed `X-Forwarded-For`; set `trusted_proxies`
accurately when running behind a reverse proxy or load balancer. The firewall is
a coarse network gate, not a substitute for authentication.

## XSRF / CSRF protection

`[security] xsrf` enables double-submit-cookie CSRF protection (`"off"` by
default). It is defense in depth for browser deployments that authenticate with
cookies or HTTP Basic; an API driven only with `X-API-Key` or
`Authorization: Bearer` headers does not strictly need it, and the
`application/json` body requirement plus the locked-down [CORS](#cors) policy
already make `/pathql` hard to drive from a cross-site form.

When `xsrf = "on"`:

- A safe request (`GET`/`HEAD`/`OPTIONS`) that arrives without an `XSRF-TOKEN`
  cookie is given a fresh one. The cookie is `SameSite=Strict` and (over TLS)
  `Secure`, and is deliberately readable by JavaScript so a first-party client
  can echo it back.
- A state-changing request (`POST`/`PUT`/`PATCH`/`DELETE`) must send an
  `X-XSRF-TOKEN` header equal to the `XSRF-TOKEN` cookie, or it is rejected with
  `403`. Because the same-origin policy stops a cross-site page from reading the
  cookie, only first-party code can produce a matching header.

The intended flow is: make one safe request to obtain the cookie, then include
its value in the `X-XSRF-TOKEN` header on every later unsafe request. The check
applies to `/pathql` and the `/admin/*` routes.

## Operations / hardening

- Run the application as a least-privilege, `SELECT`-only database role and rely
  on row-level security, not the application, as the last line of defense. See
  [examples/rls_policy.sql](examples/rls_policy.sql) for the grants and revokes
  (no write access, no `COPY`, no `pg_read_file` / `pg_sleep` / large-object
  functions).
- Keep `config.ini` readable only by the server user (`chmod 600`). The server
  logs a warning at startup if the file is group- or world-accessible.
- Serve over TLS, either here or at a reverse proxy, and keep `trusted_proxies`
  accurate so the rate limiter cannot be bypassed with a spoofed
  `X-Forwarded-For`.
- Run `govulncheck ./...` in CI to catch known vulnerabilities in the toolchain
  and dependencies, and keep the Go toolchain patched (standard-library fixes
  ship in patch releases).

## Running

```sh
go build -o pathql-server
./pathql-server
```

The server listens on `listen` (default `:8000`) and serves `POST /pathql`
(execute queries), `GET /schema` ([reflect the schema as DBML](#schema-reflection)),
`GET /health` ([readiness probe](#health-check)) and `GET /metrics` (request
metrics). Because `top_queries` exposes raw query text, `/metrics` is authorized
only for the configured `metrics_user` principal, who may read metrics and
nothing else, see [Metrics](#metrics). At startup the server also runs a database
hardening self-check, see [Startup hardening checks](#startup-hardening-checks).
It shuts down gracefully on SIGINT/SIGTERM.

## Startup hardening checks

Almost every guarantee here (read-only, least privilege, no file access, RLS on
every table) depends on the database role and grants being set up correctly,
off-server. With `startup_checks` set, the server verifies the connected role's
actual posture once at startup using read-only catalog queries, and reports what
it finds:

- **Critical**: the role is a superuser or has the `BYPASSRLS` attribute (either
  bypasses RLS and read-only), or it can write
  (`INSERT`/`UPDATE`/`DELETE`) to tables outside the auth tables. In `enforce`
  mode under `login_role`, a readable table with **no** row-level security is
  also critical, since it is a silent full-table exposure where RLS is the
  boundary.
- **Warning**: the role can execute sensitive functions (`pg_read_file`,
  `pg_sleep`, large-object functions, ...); it can read tables that have no
  row-level security (so every authenticated caller sees all their rows); it
  **owns** a table whose RLS is enabled but **not forced** (a table owner
  bypasses its own non-forced policies, so apply `FORCE ROW LEVEL SECURITY`); or
  a table has RLS enabled but **no policy** (a safe default-deny, reported so an
  intentional lockdown is not mistaken for a missing one).

`startup_checks = "warn"` (the default) logs the findings and keeps running;
`"enforce"` additionally refuses to start when there is a critical finding;
`"off"` skips the check. The checks are PostgreSQL-only and are skipped for other
drivers. See [examples/rls_policy.sql](examples/rls_policy.sql) for the grants
and revokes that make them pass.

## SQL gate

The SQL gate is an optional, pre-execution validator that narrows the
"send SQL, get JSON" surface before a query reaches the database. The database
remains the real boundary (a least-privilege role, the read-only transaction,
and RLS); the gate is defense in depth that rejects classes of query those
controls do not fully cover. It is set with `[security] sql_gate` and is `"off"`
by default.

When `sql_gate = "on"`, a query is rejected with `400` (and a clean,
shape-describing message) unless it is:

- **a single statement** - stacked statements (`SELECT ...; DROP ...`) are
  rejected even where a driver would run them;
- **read-only** - it must begin with `SELECT`, `WITH`, `TABLE` or `VALUES`, so
  `SET`, `SHOW`, `EXPLAIN`, `COPY`, `CALL`, `DO` and any DDL/DML are refused at
  the edge (several of these run even inside a `READ ONLY` transaction); and
- **free of system catalogs** - no identifier may name `information_schema` or
  start with the reserved `pg_` prefix, closing off catalog enumeration
  (`pg_class`, `pg_authid`, `pg_stat_activity`, ...) that row-level security does
  not protect.

The check is content-aware: a `;`, a `pg_` name, or a keyword that appears
inside a string literal, a quoted identifier, a comment, or a dollar-quoted body
does not trigger a rejection. The value is a string so stricter modes (table or
column allowlists, a forced `LIMIT`) can be added later without breaking
existing configs.

## Cost ceiling

The cost ceiling rejects a query *before running it* when the PostgreSQL planner
estimates it would be too expensive. With `[limits] max_estimated_cost` or
`max_estimated_rows` set above `0`, the server runs `EXPLAIN (FORMAT JSON)` on
the query first (inside the same read-only transaction, with the same bound
parameters, and bounded by the same `statement_timeout`). Plain `EXPLAIN` only
asks the planner for an estimate; it never executes the query, so the check has
no side effects. If the top node's estimated total cost exceeds
`max_estimated_cost`, or its estimated output rows exceed `max_estimated_rows`,
the request is rejected with `400` and a generic message; the actual estimate
and the limit are logged server-side, not returned, so data volume is not
disclosed.

Both bounds default to `0` (disabled). `max_estimated_cost` is in PostgreSQL
planner cost units (the same units `EXPLAIN` prints), so pick a value by running
`EXPLAIN` on representative and pathological queries. The check is PostgreSQL
only; it is skipped for other drivers. It is one EXPLAIN round-trip per request,
so enable it when you accept queries from untrusted callers and want to stop a
sequential scan over a huge table or an accidental cross join before it ties up a
connection.

Enable the [SQL gate](#sql-gate) alongside the cost ceiling. The gate restricts
each request to a single read-only statement, so the EXPLAIN the ceiling runs
plans exactly that one statement; without it a stacked statement could be planned
or run during the EXPLAIN step (the read-only transaction still blocks writes,
but the gate is the cleaner boundary).

## Writes

The server is read-only by default: every query runs in a `READ ONLY`
transaction and the role is granted only `SELECT`. Set `[security] writes = "on"`
to also accept data-modifying statements. It is off by default, and it cannot be
combined with `read_only = true` (that would block every write at the database;
the server refuses to start on the contradiction).

When writes are on, each request is classified by its leading statement keyword:

- a **read** (`SELECT`/`TABLE`/`VALUES`) runs in a `READ ONLY` transaction,
  exactly as when writes are off, so enabling writes never relaxes the read path;
- a **write** (`INSERT`/`UPDATE`/`DELETE`, or a `WITH` wrapping one) runs in a
  read-write transaction; and
- anything else (DDL, `TRUNCATE`, `COPY`, `SET`, `SHOW`, `EXPLAIN`, `CALL`, `DO`,
  stacked statements, system-catalog access) is rejected with `400`.

Classification applies the same structural rules as the [SQL gate](#sql-gate) (a
single statement over non-catalog objects) no matter how `sql_gate` is set.
Enabling writes therefore has no side effects: stacked statements and catalog
access stay blocked either way.

### Response shape

- A write **with `RETURNING`** returns the written rows as JSON, subject to
  `max_response_bytes`. pathsqlx infers nesting from a `SELECT ... FROM` shape, so
  it does not auto-nest a write: the `RETURNING` columns come back under their
  bare names (a flat array). Shape the response with `paths` hints, exactly as for
  a read (for example `"paths": {"$": "$"}`).
- A write **without `RETURNING`** returns `{"affected": N}`, the number of rows
  changed.

`RETURNING` is PostgreSQL syntax (full `INSERT`/`UPDATE`/`DELETE`); MariaDB
supports it only for `INSERT` and `DELETE`. The affected-count path works on any
driver.

### Blast-radius cap

`[limits] max_affected_rows` (0 disables, the default) is the write-side analogue
of the [cost ceiling](#cost-ceiling). A write that affects (or, with `RETURNING`,
returns) more rows than the cap is rolled back before commit and rejected with
`400`; the actual count is logged server-side, not returned. The pre-execution
`max_estimated_rows` ceiling also applies, so an obviously unbounded `UPDATE`/
`DELETE` is stopped before it runs.

### Tenant isolation for writes

Writes are only tenant-isolated under
[`identity_kind = "login_role"`](#row-level-security), where the connected role is
the caller's own. RLS read policies are not enough: a `USING` clause filters which
rows a write can *see*, but only a `WITH CHECK` clause constrains which rows a
caller can *create or change*. Without `WITH CHECK`, a caller could insert or
update a row attributed to another tenant. Add `FOR INSERT`/`FOR UPDATE` policies
with `WITH CHECK (owner = current_user)` (and a `FOR DELETE` policy with `USING`);
see the optional writer block in
[examples/rls_policy.sql](examples/rls_policy.sql). Under `login_role` with
`startup_checks = "enforce"`, the server refuses to start when a writable table
has no `WITH CHECK` policy, so a silent cross-tenant write path is caught at boot.

Under `identity_kind = "none"` there is no per-caller identity, so writes are
trusted single-tenant: every authenticated caller writes as the same role with no
row-level authorization. The server logs a warning at startup in that case. For
browser deployments that authenticate with cookies or HTTP Basic, enable
[`xsrf = "on"`](#xsrf--csrf-protection) once writes are accepted.

### Example: insert returning the new row

**Request:**

```json
{
  "query": "INSERT INTO posts (content) VALUES (:content) RETURNING id, content",
  "params": { "content": "hello" },
  "paths": { "$": "$" }
}
```

**Response:**

```json
{ "id": 3, "content": "hello" }
```

### Example: update without RETURNING

**Request:**

```json
{
  "query": "UPDATE posts SET content = :content WHERE id = :id",
  "params": { "content": "edited", "id": 3 }
}
```

**Response:**

```json
{ "affected": 1 }
```

## Testing

The default suite is hermetic (no database needed):

```sh
go test ./...
```

End-to-end tests drive the real HTTP stack against a live PostgreSQL: they seed
the auth tables and a row-level-security demo table, then exercise API-key,
Basic and JWT authentication, RLS isolation per principal, read-only
enforcement and rate limiting over HTTP. They are
behind the `e2e` build tag and skip cleanly when no database is reachable:

```sh
# Uses host=localhost user=pathql password=pathql dbname=pathql by default.
go test -tags e2e -run TestE2E ./...

# Or point at your own database:
PATHQL_E2E_DSN="host=... user=... password=... dbname=... sslmode=disable" \
  go test -tags e2e -run TestE2E ./...
```

Each run isolates its tables under a process-specific prefix and drops them on
completion.

## Request format

```json
{
  "query": "SELECT id, content FROM posts WHERE id = :id",
  "params": { "id": 1 },
  "paths": { "posts": "$.posts" }
}
```

Request parameters:

- **`query`** (required): SQL query string
- **`params`** (optional): Named parameters for the query (must be an object,
  not an array)
- **`paths`** (optional): PATH hints to override automatic JSON path inference.
  Each key is a table alias, and each value is the JSON path (e.g.,
  `{"p": "$", "c": "$.comments[]"}`)

On error the response is a generic JSON body
(`{"type":"Error","message":"..."}`); driver internals are logged server-side,
never returned to the client.

## Metrics

`GET /metrics` on the main listener returns JSON with request statistics. It is
authenticated like any request and then authorized: only the principal whose
`app_user` equals `metrics_user` (default `"metrics"`) may read it, and that
principal is forbidden on `/pathql`. Any other identity gets `403`, and a missing
or invalid credential gets `401`. An empty `metrics_user`, or auth being
disabled, makes the endpoint return `403` for everyone (fail closed), since no
request can present the metrics identity. Create the metrics principal like any
other user (see [Auth tables](#auth-tables)); an API-key-only account with
`app_user = 'metrics'` is typical. The response looks like:

```json
{
  "status_codes": {
    "200": 1523,
    "400": 12,
    "500": 3,
    "other": 0
  },
  "latency_ms": {
    "<1": 45,
    "<5": 892,
    "<10": 421,
    "<50": 123,
    "<100": 34,
    "<500": 7,
    "<1000": 1,
    "<5000": 0,
    "<10000": 0,
    ">=10000": 0
  },
  "auth": {
    "success": 1502,
    "failure": 33
  },
  "rejections": {
    "429": 7,
    "503": 0
  },
  "top_queries": [
    {"query": "SELECT * FROM users WHERE id = :id", "count": 18234, "total_ms": 41210},
    {"query": "SELECT * FROM posts", "count": 9120, "total_ms": 33870}
  ],
  "top_users": [
    {"user": "alice", "count": 12044, "total_ms": 51230},
    {"user": "bob", "count": 5310, "total_ms": 18900}
  ]
}
```

Status codes, latency buckets, and auth counters are tracked using atomic
64-bit counters and are safe for concurrent access. `auth.success` and
`auth.failure` count successful and failed authentications. `rejections.429` and
`rejections.503` count abuse-protection rejections from the rate limiter and the
per-user / global concurrency caps.

`top_queries` lists the queries that consumed the most total time, with the
request count and accumulated duration (`total_ms`) for each. It uses the
Space-Saving algorithm, which keeps a bounded set of counters (up to 1000
distinct queries) and evicts the entry with the lowest accumulated duration when
full, so memory stays bounded regardless of how many distinct queries the server
sees.

`top_users` is the same, keyed by the authenticated `app_user` instead of the
query: it ranks identities by the total request-handling time attributed to
them, with the request count and accumulated duration for each. It uses the same
bounded Space-Saving counter (up to 1000 distinct identities), and only
authenticated requests are attributed (the metrics principal is excluded, since
it is refused on `/pathql`).

## Health check

`GET /health` is an unauthenticated readiness probe for load balancers and
orchestrators. It returns `200` with `{"status":"ok","database":"up"}` when the
database answered a recent ping, and `503` with
`{"status":"unavailable","database":"down"}` when it did not, so an orchestrator
keeps traffic away until the database is reachable. The reachability result is
cached for about a second, so frequent probes (or a flood of requests) cannot
turn the endpoint into a database-load amplifier. It is intentionally exempt from
authentication, rate limiting and the concurrency caps so a probe always gets a
prompt answer; the [IP firewall](#ip-firewall), if configured, still applies.

## Schema reflection

`GET /schema` returns the tables, columns, primary keys and foreign keys the
caller can read, rendered as [DBML](https://dbml.dbdiagram.io/) by the
[dbml-tools](https://github.com/mevdschee/dbml-tools) library, so a client can
discover what to query (table names, columns, and the foreign-key relationships
PathQL nests on) without any write access or DDL. The response is `text/plain`
DBML:

```dbml
Project {
  database_type: 'PostgreSQL'
}

Table "posts" {
  "id" bigint [pk, not null]
  "category_id" bigint [not null]
  "content" text
}

Ref: "posts"."category_id" > "categories"."id"
```

It is read-only and PostgreSQL-only (other drivers get `501`). It authenticates
like `/pathql` and runs on the caller's own connection, so in
[`login_role`](#row-level-security) mode PostgreSQL's `information_schema`
restricts the output to exactly the tables that role was granted, the same set
the caller can query. The metrics and admin principals are forbidden, and the
response is subject to `max_response_bytes`.

## Examples

The examples below are based on a database with `posts`, `comments`, and
`categories` tables.

### Simple query: flat array

**Request:**

```json
{
  "query": "SELECT id, content FROM posts WHERE id = :id",
  "params": { "id": 1 }
}
```

**Response:**

```json
[{ "id": 1, "content": "blog started" }]
```

### Multiple records

**Request:**

```json
{
  "query": "SELECT id FROM posts WHERE id <= 2 ORDER BY id",
  "params": {}
}
```

**Response:**

```json
[{ "id": 1 }, { "id": 2 }]
```

### Join with automatic inference: posts with comments

Using table aliases (`p`, `c`), pathsqlx automatically detects the one-to-many
relationship via foreign keys. Each result row holds the post under `p` and its
comments as a sibling `c` array, grouped per post:

**Request:**

```json
{
  "query": "SELECT p.id, c.id, c.message FROM posts p LEFT JOIN comments c ON c.post_id = p.id WHERE p.id <= 2 ORDER BY p.id, c.id",
  "params": {}
}
```

**Response:**

```json
[
  {
    "p": { "id": 1 },
    "c": [{ "id": 1, "message": "great!" }, { "id": 2, "message": "nice!" }]
  },
  {
    "p": { "id": 2 },
    "c": [{ "id": 3, "message": "interesting" }, { "id": 4, "message": "cool" }]
  }
]
```

### PATH hint: nested posts with comments

Using a PATH hint to control the root structure:

**Request:**

```json
{
  "query": "SELECT posts.id, comments.id FROM posts LEFT JOIN comments ON post_id = posts.id WHERE posts.id <= 2 ORDER BY posts.id, comments.id",
  "params": {},
  "paths": { "posts": "$.posts" }
}
```

**Response:**

```json
{
  "posts": [
    { "id": 1, "comments": [{ "id": 1 }, { "id": 2 }] },
    { "id": 2, "comments": [{ "id": 3 }, { "id": 4 }] }
  ]
}
```

### PATH hint: count as object

**Request:**

```json
{
  "query": "SELECT count(*) AS posts FROM posts p",
  "params": {},
  "paths": { "p": "$" }
}
```

**Response:**

```json
{ "posts": 2 }
```

### PATH hint: nested statistics object

**Request:**

```json
{
  "query": "SELECT count(*) AS posts FROM posts p",
  "params": {},
  "paths": { "p": "$.statistics" }
}
```

**Response:**

```json
{ "statistics": { "posts": 2 } }
```

### PATH hint: multiple scalar counts

**Request:**

```json
{
  "query": "SELECT (SELECT count(*) FROM posts) as posts, (SELECT count(*) FROM comments) as comments",
  "params": {},
  "paths": { "$": "$.statistics" }
}
```

**Response:**

```json
{ "statistics": { "posts": 2, "comments": 4 } }
```

### Group by

**Request:**

```json
{
  "query": "SELECT categories.name AS name, count(posts.id) AS post_count FROM posts, categories WHERE posts.category_id = categories.id GROUP BY categories.name ORDER BY categories.name",
  "params": {}
}
```

**Response:**

```json
[{ "name": "announcement", "post_count": 2 }]
```

Only `announcement` appears: both posts belong to it, and the inner join
excludes `article`, which has no posts.

## License

See [LICENSE](LICENSE).
