# pathql-server

PathQL server implementation in Go using Mux (see: [PathQL.org](https://pathql.org/)).

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

## Configuration

Create a `config.ini` file in the project root. It is TOML:

```ini
driver  = "postgres"
dsn     = "host=localhost port=5432 user=pathql_app password=${PATHQL_DB_PASSWORD} dbname=pathql sslmode=disable"
listen  = ":8000"
verbose = false

[database]
max_open_conns       = 50
max_idle_conns       = 10
conn_max_lifetime_ms = 300000

[security]
auth_table_prefix           = "pathql_auth_"
session_variable            = "app.user"
read_only                   = true
metrics_user                = "metrics"
startup_checks              = "warn"
# trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]

[auth]
methods        = ["apikey", "basic"]
api_key_header = "X-API-Key"

[limits]
max_query_ms              = 5000
max_body_bytes            = 1048576
max_response_bytes        = 10485760
max_concurrent_per_user   = 10
max_concurrent_global     = 200
max_requests_per_min_ip   = 120
max_auth_failures_per_min = 60
work_mem_kb               = 0

[timeouts]
read_ms  = 10000
write_ms = 30000
idle_ms  = 60000

[cache]
backend   = "embedded"
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
- **`dsn`**: database connection string. The server holds one fixed credential.
- **`listen`**: listen address serving `POST /pathql` and `GET /metrics`
  (default `:8000`).
- **`verbose`**: verbose logging (default `false`). When enabled, logs
  timestamp, status code, response size, and latency for each request.

Section options:

- **`[database]`**: connection-pool caps for the single shared pool
  (`max_open_conns`, `max_idle_conns`, `conn_max_lifetime_ms`).
- **`[security]`**: see [Row-level security](#row-level-security).
  `auth_table_prefix` namespaces
  the auth tables. `metrics_user` is the principal allowed to read `/metrics`
  (see [Metrics](#metrics)). `startup_checks` controls the
  [startup hardening check](#startup-hardening-checks). `trusted_proxies` is a
  list of CIDRs (or bare IPs) whose `RemoteAddr` is trusted to set
  `X-Forwarded-For` / `X-Real-IP`; the rate limiter uses it to find the real
  client IP.
- **`[auth]`**: see [Authentication](#authentication).
- **`[limits]`**: `max_body_bytes` caps the request body and `max_response_bytes`
  caps the encoded response (an oversized result is rejected with `413`).
  `max_query_ms` bounds each query (a Go-side request timeout plus a Postgres
  `statement_timeout`, `idle_in_transaction_session_timeout`, and an optional
  `work_mem_kb`). `max_concurrent_per_user`, `max_concurrent_global`,
  `max_requests_per_min_ip` and `max_auth_failures_per_min` are the
  abuse-protection caps, see
  [Rate limiting and concurrency](#rate-limiting-and-concurrency).
- **`[timeouts]`**: HTTP server `read_ms`, `write_ms`, and `idle_ms`.
- **`[cache]`**: the in-process counter/JWKS cache, see [Cache](#cache).
- **`[tls]`**: optional TLS termination, see [TLS](#tls).
- **`[cors]`**: `allowed_origins` is an explicit list of origins for browser
  cross-origin access, see [CORS](#cors).

### Secrets

The DB password should not live in the file in clear text. The `dsn` value
supports `${ENV}` expansion, so put the password in an environment variable and
reference it, for example `password=${PATHQL_DB_PASSWORD}`. Tokens that are not
set expand to the empty string. Alternatively, set `PATHQL_DSN` in the
environment to override the file `dsn` entirely (used verbatim, no expansion).
Keep `config.ini` readable only by the server user (`chmod 600`).

## Authentication

Authentication is configured in the `[auth]` section. `methods` is an ordered
list; each request is tried against each method until one succeeds. Supported
methods are `"apikey"`, `"basic"`, and `"jwt"`. Leaving `methods` empty disables
authentication entirely; the server logs a clear warning at startup when it
does.

- **`apikey`**: presented as `Authorization: ApiKey <key>` or in the header
  named by `api_key_header` (default `X-API-Key`). The server stores only a
  SHA-256 hash of the key and looks it up by a non-secret prefix.
- **`basic`**: standard HTTP Basic; the password is verified against a bcrypt
  hash. Use it only over TLS.
- **`jwt`**: a bearer token presented as `Authorization: Bearer <jwt>`, see
  [JWT](#jwt).

Failed authentication returns `401` with a generic body and a
`WWW-Authenticate` header. The response never reveals which field was wrong.

Once a request authenticates, the resolved `app_user` is bound to the Postgres
session for the query, see [Row-level security](#row-level-security).

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

Every query runs inside a read-only transaction (when `read_only = true`) on a
single connection, with the authenticated identity bound to a Postgres session
variable named by `session_variable` (default `app.user`). The bind uses
`set_config(name, value, true)`, the function form of `SET LOCAL`, so the value
is a bound parameter rather than concatenated SQL and the setting is scoped to
that transaction. A `statement_timeout` matching `max_query_ms` is set the same
way.

Your row-level-security policies read that value with
`current_setting('app.user', true)`. The `true` makes the lookup return NULL
instead of erroring when the variable is unset, so a query that arrives without
an authenticated identity simply matches no rows. A runnable example, including
the policy, the `ENABLE ROW LEVEL SECURITY` statements, and the least-privilege
grants for the application role, is in
[examples/rls_policy.sql](examples/rls_policy.sql).

The session variable name must be schema-qualified (contain a dot) and is
validated before use. When no identity is present, no session variable is set.

## Identity model (session_guc vs login_role)

`[security] identity_kind` selects how the caller's identity reaches row-level
security:

- **`session_guc`** (default): the server binds the authenticated identity with
  `set_config('app.user', ..., true)` and policies read `current_setting('app.user', true)`,
  as described above. One shared pool serves every request. The GUC is only as
  trustworthy as the query, though: a caller running arbitrary SQL can
  `set_config('app.user', ...)` to another value, so this mode leans on
  `block_multiple_statements` and suits single-tenant or trusted-caller setups.
- **`login_role`**: the server connects to PostgreSQL **as the caller's own
  database role** and policies read `current_user`. Because the role is fixed by
  authentication and the role system enforces membership, a query cannot forge
  another identity, even in a single statement. This is the robust choice for
  multi-tenant RLS. See [examples/login-role](examples/login-role/) for a runnable
  setup and [ROLE_MANAGEMENT_PLAN.md](ROLE_MANAGEMENT_PLAN.md) for the design.

### login_role configuration

`login_role` is configured under `[roles]` and needs at least one auth method:

- **`base_dsn`**: the connection string **without** a user; the server appends
  `user=<role>` per connection. Authentication is trust/peer on an isolated
  channel (or client cert + `pg_ident`), so no per-user password is stored.
- **`baseline_role`**: the role used for pre-auth work (reading the auth tables)
  before the caller is known. Default `pathql_auth`.
- **`prefix`**: a user with id N maps to the login role `<prefix>N`
  (default `pathql_r_`); the role name is derived from the id.
- **`reader_role`**: a group role granting read access that every managed role is
  a member of (default `pathql_readers`). Managed roles are never members of each
  other.
- **`auth`**: how the per-role connections authenticate. `trust` (default) relies
  on trust/peer on an isolated channel and stores no secret. `password` derives
  each role's password as `HMAC(password_secret, role)`, includes it in the sync
  DDL (`CREATE ROLE ... PASSWORD`), and re-derives it at connect time, so no
  per-role secret is stored; pair it with `scram-sha-256` in `pg_hba.conf` for
  production. `password_secret` is required for `password` and is `${ENV}`-expandable;
  the `baseline_role` must also have that derived password set.
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
- **`GET`/`PUT /admin/pool`**: read or set the global pool defaults (persisted,
  applied live), with per-pool `db.Stats`. login_role only.
- **`PUT`/`DELETE /admin/users/{id}/pool`**: set or clear a per-user pool
  override. login_role only.

## Multiple statements

With `block_multiple_statements = true` (the default), a query that contains more
than one statement is rejected with a generic `400` before it reaches the
database. The check is a conservative lexical scan: it counts a `;` that is not
inside a string literal, a quoted identifier, a dollar-quoted string, or a
comment. A single optional trailing `;` is allowed. This is not a full SQL
parser, it errs toward rejection, so a query it is unsure about is refused rather
than passed through. Combined with the read-only transaction and a
least-privilege role, it blocks stacked-query injection such as
`SELECT 1; DROP TABLE ...`.

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
counters and for caching fetched JWKS documents. Only the `embedded` backend is
supported; it is bounded to `memory_mb` MiB. `auth_ttl` and `jwks_ttl` are
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

The server listens on `listen` (default `:8000`) and serves both
`POST /pathql` (execute queries) and `GET /metrics` (request metrics). Because
`top_queries` exposes raw query text, `/metrics` is authorized only for the
configured `metrics_user` principal, who may read metrics and nothing else, see
[Metrics](#metrics). At startup the server also runs a database hardening
self-check, see [Startup hardening checks](#startup-hardening-checks). It shuts
down gracefully on SIGINT/SIGTERM.

## Startup hardening checks

Almost every guarantee here (read-only, least privilege, no file access, RLS on
every table) depends on the database role and grants being set up correctly,
off-server. With `startup_checks` set, the server verifies the connected role's
actual posture once at startup using read-only catalog queries, and reports what
it finds:

- **Critical**: the role is a superuser (it bypasses RLS and read-only), or it
  can write (`INSERT`/`UPDATE`/`DELETE`) to tables outside the auth tables.
- **Warning**: the role can execute sensitive functions (`pg_read_file`,
  `pg_sleep`, large-object functions, ...), or it can read tables that have no
  row-level security (so every authenticated caller sees all their rows).

`startup_checks = "warn"` (the default) logs the findings and keeps running;
`"enforce"` additionally refuses to start when there is a critical finding;
`"off"` skips the check. The checks are PostgreSQL-only and are skipped for other
drivers. See [examples/rls_policy.sql](examples/rls_policy.sql) for the grants
and revokes that make them pass.

## Testing

The default suite is hermetic (no database needed):

```sh
go test ./...
```

End-to-end tests drive the real HTTP stack against a live PostgreSQL: they seed
the auth tables and a row-level-security demo table, then exercise API-key,
Basic and JWT authentication, RLS isolation per principal, read-only
enforcement, multi-statement blocking and rate limiting over HTTP. They are
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
