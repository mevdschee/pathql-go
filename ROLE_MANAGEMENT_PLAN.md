# Role and pool management plan

This plans two related runtime features for pathql-server: provisioning and
deprovisioning a PostgreSQL role per user when the user is added or removed
through admin routes, and tuning the connection pool through admin routes. It
builds on the login_role RLS model (identity is `current_user`, the connection
authenticates as the user's role).

Decisions locked (this revision): build the login_role layer first; per-role
connections authenticate via trust/peer on an isolated channel (no per-user
password); the server does NOT hold CREATEROLE, it emits the exact DDL to sync
roles which a cron job applies out of band; admin routes live on the main
listener gated to `admin_user`.

## 1. Goal and scope

- The server creates a database role when a user is added and drops it when the
  user is removed, both through admin routes, so login_role RLS works without a
  human running DDL per user.
- The server exposes pool parameters through admin routes, persisted so changes
  survive a restart.
- Out of scope: the static setup (protected tables, RLS policies, the shared
  reader role) stays a deploy-time concern handled by the sibling rls-polyfill.
  This document covers only the dynamic, per-user lifecycle at runtime.
- Roles are per user. Tenant-scoped roles and pools are not part of this plan;
  tenancy, if needed, is expressed in the static RLS policies, not in the
  server's dynamic role management.

## 2. Prerequisite: login_role connection model

This plan assumes the login_role connection layer exists:

- A mapping from the app-authenticated principal to a database role.
- A per-role connection pool, where each connection authenticates as the user's
  role (client cert plus a `pg_ident` map, or trust/peer on an isolated channel),
  so no per-user password is stored.
- RLS policies keyed on `current_user`.

If that layer is not yet built it becomes phase 0 of the build order below.

## 3. Identity model

- Role name is derived by the server, never taken from request text:
  `<prefix><user_id>`, where `user_id` is the integer primary key of the user
  row and `<prefix>` is configurable and validated against
  `^[a-z_][a-z0-9_]*$`. The full name must be a valid identifier within 63 bytes.
- The generated name is stored in a `db_role` column on the user row, so removal
  is unambiguous and never reconstructed from user input.
- All DDL quotes the name with `format('%I', ...)` even though it is
  server-generated.

## 4. Role sync via emitted DDL (no CREATEROLE in the server)

The server never runs role DDL and never holds `CREATEROLE`, which keeps its
blast radius small. Instead it computes the exact DDL needed to make the login
roles match the users table, and an operator cron job applies that DDL out of
band as a privileged role.

- A `sync` capability (an admin route plus an offline command) inspects
  `pg_roles` and the auth tables and emits an ordered, idempotent DDL script:
  `CREATE ROLE` (LOGIN, NOSUPERUSER, NOCREATEROLE) for users with no role,
  `GRANT <reader_role>` for roles missing read access, and `DROP ROLE IF EXISTS`
  for managed-prefixed roles whose user is gone.
- It only ever emits DDL for roles whose name matches the managed prefix and
  never touches an unmanaged role; identifiers are quoted.
- The cron job runs the emitted DDL with a CREATEROLE role. The server only reads
  the catalog to produce the diff, which the baseline connection can do.
- Role creation therefore lags user creation by one cron cycle: a freshly added
  user cannot connect until the sync runs. The add-user response reports the
  pending role so an operator can run the sync immediately when needed.

This is the `internal/roles` package (built first, in the background).

## 5. Persistence

Runtime state lives in the database so it survives a restart; config.ini seeds
the initial values.

- `pathql_pool_settings`: a single row holding the global pool defaults
  (`max_open_conns`, `max_idle_conns`, `conn_max_lifetime_ms`,
  `conn_max_idle_time_ms`). Created from the config.ini values on first boot if
  absent; authoritative at runtime.
- `pathql_auth_users` gains `db_role` (the managed role name) and, if per-user
  overrides are kept (open decision), nullable
  `pool_max_open` / `pool_max_idle` / `pool_conn_max_lifetime_ms` /
  `pool_conn_max_idle_time_ms`, where null means inherit the global default.
- Bootstrap reads `pathql_pool_settings` over a connection opened from the
  config.ini defaults, then applies it.

## 6. Admin routes

All gated to a dedicated `admin_user` principal (fail closed when empty), the
same model as the metrics user, plus audit logging with the request id and the
resolved admin identity, and the existing rate limits. TLS is expected.

User lifecycle:

- `POST /admin/users` create a user, provision its role.
- `DELETE /admin/users/{id}` remove a user, deprovision its role.

Pool configuration:

- `GET /admin/pool` effective global params, any per-user overrides, and live
  `db.Stats()` per pool and aggregate (open, in use, idle, wait count, wait
  duration).
- `PUT /admin/pool` set the global defaults.
- `PUT /admin/users/{id}/pool` and `DELETE /admin/users/{id}/pool` set or clear a
  per-user override (only if overrides are kept).

## 7. Role lifecycle operations

`CREATE ROLE`, `GRANT`, and `DROP ROLE` are transactional in PostgreSQL and the
auth tables are in the same database, so each operation is one atomic transaction
on the provisioner connection, with no orphan role or row on failure.

Create:

```
BEGIN;
  INSERT INTO pathql_auth_users(...) RETURNING id;   -- derive role name from id
  CREATE ROLE <role> LOGIN NOSUPERUSER NOCREATEROLE INHERIT;
  GRANT pathql_readers TO <role>;
  UPDATE pathql_auth_users SET db_role = <role> WHERE id = ...;
COMMIT;
```

A duplicate role (SQLSTATE 42710) is treated as success after verifying the name
is managed.

Delete:

```
-- evict the per-role pool and pg_terminate_backend any lingering sessions first
BEGIN;
  DELETE FROM pathql_auth_api_keys WHERE user_id = $1;
  DELETE FROM pathql_auth_users     WHERE id = $1;
  DROP OWNED BY <role>;
  DROP ROLE IF EXISTS <role>;
COMMIT;
```

Read-only managed roles own no objects, so `DROP OWNED BY` only clears grants;
`DROP ROLE IF EXISTS` then succeeds.

## 8. Connection pool manager

- A map of role to pool, each created lazily on first request for that role with
  the current effective parameters.
- A global weighted semaphore sized at `max_total_backends`. Every checkout
  acquires from it before using a connection. PostgreSQL has no cross-pool limit
  and `database/sql` has no global cap, so this semaphore is what bounds the total
  number of backends regardless of how many role pools exist or what per-pool
  values are set. It is the hard ceiling.
- `warm_pool_limit` caps how many role pools keep a warm idle connection; an LRU
  evicts idle connections from pools beyond the limit. The pool struct can remain
  with zero open connections.
- A re-apply operation pushes changed parameters onto live pools via
  `SetMaxOpenConns` / `SetMaxIdleConns` / `SetConnMaxLifetime` /
  `SetConnMaxIdleTime`, all of which take effect without a restart.
- Per-pool `db.Stats()` is exposed to `GET /admin/pool`.

## 9. Runtime pool parameters

- API mutable and persisted: the global defaults, and the per-user overrides if
  kept. Writes update the table and re-apply to live pools.
- Config only, never exposed by the API: `max_total_backends` and
  `warm_pool_limit`. These are the guardrails the API must not be able to raise.
- Validation: `max_open >= 1` (no unlimited, which would let one pool exhaust the
  database), `max_idle <= max_open`, any per-pool `max_open` clamped to
  `max_total_backends`, sane duration ranges. The semaphore is the backstop if
  validation is ever bypassed.

## 10. Reconciliation

A report-only pass, runnable at startup or as an admin action, like the hardening
check:

- For each user, ensure the managed role exists with reader membership; create
  any that are missing.
- Report managed-prefixed roles with no user row as orphans. Never auto-drop;
  destruction stays an explicit admin action.

## 11. Configuration additions

```ini
[database]
# existing seeds: max_open_conns, max_idle_conns, conn_max_lifetime_ms
conn_max_idle_time_ms = 60000
max_total_backends    = 200   # hard ceiling, config only

[roles]
manage          = true
prefix          = "pathql_r_"
reader_role     = "pathql_readers"
warm_pool_limit = 64          # config only
provisioner_dsn = "host=... user=pathql_provisioner password=${...} ..."

[security]
admin_user = "admin"          # principal allowed on /admin/*; empty disables them
```

## 12. Security rails

- CREATEROLE only on the isolated provisioner connection; never the query or
  reader roles; not a superuser.
- Managed roles are `LOGIN NOSUPERUSER NOCREATEROLE`, members only of the reader
  role, never of each other (the pivot risk).
- LOGIN roles are only safe because `pg_hba` restricts who may connect as them
  (the login_role cert or trust setup); the plan documents that pg_hba must not
  expose them more widely.
- Prefix plus recorded-as-managed check on every drop; `%I` quoting; idempotent
  create and delete.
- Admin routes gated to `admin_user`, audited, rate limited, TLS expected;
  optionally bound to a separate or loopback listener.

## 13. Testing

- Hermetic: name derivation and validation, the prefix and managed guards reject
  unmanaged names, request validation, admin gating, pool parameter validation.
- Against a throwaway PostgreSQL: provision a user, the role exists with reader
  membership, connects, and is RLS isolated; remove the user, the role is gone and
  the pool evicted with no orphan; the prefix guard refuses to drop an unmanaged
  role; a live `PUT /admin/pool` changes pool behavior; the global ceiling holds
  even with absurd per-pool values; per-user override precedence; settings persist
  across a restart; reconcile creates a missing role and reports an orphan without
  dropping it.

## 14. Build order

0. (Prerequisite) login_role connection layer: principal to role mapping,
   per-role authentication, per-role pools, `current_user` policies.
1. Provisioner connection, name derivation, prefix and managed guards.
2. Role lifecycle SQL behind a small `roles` package, tested against throwaway
   PostgreSQL.
3. Admin routes and `admin_user` gating, audit and rate limiting.
4. Pool manager: global semaphore, warm-pool LRU, live re-apply, per-pool stats.
5. Runtime pool parameters: persistence tables, the pool routes, validation.
6. Reconcile, report-only, wired into startup.
7. Docs (README operations, config, hardening notes) and demo wiring.

## 15. Open decisions

1. login_role prerequisite: plan and build it first as phase 0, or assume the
   cert or trust plus per-role pool layer is already in place.
2. Provisioner credential: the server holds a CREATEROLE credential as planned,
   or the DDL is delegated to an admin-run step or rls-polyfill so the server
   never holds CREATEROLE (smaller blast radius, but no fully self-service admin
   route).
3. Admin route exposure: gate on `admin_user` on the main listener, or bind
   `/admin/*` to a separate or loopback listener for network isolation.
4. Per-user pool overrides: include them now, or ship global-only first and add
   overrides later.
