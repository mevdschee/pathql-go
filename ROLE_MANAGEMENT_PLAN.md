# Role management plan

This plans provisioning and deprovisioning a PostgreSQL role per user when the
user is added or removed through admin routes. It applies to the `login_role`
RLS model (identity is `current_user`, the connection authenticates as the
user's role), which is the opt-in hardened mode selected with
`[security] identity_kind = "login_role"`. The default `none` mode uses a single
shared connection with no per-user roles and is not covered here.

Connection-pool sizing is **config-only** (`[database]` and `[roles]`): there is
no runtime pool-tuning API and no pool-settings persistence table. An earlier
revision proposed `GET/PUT /admin/pool` and per-user overrides; those were
dropped to keep the admin surface small, so this document no longer covers them.

Decisions locked (this revision): per-role connections authenticate with a
per-role password derived from a master secret (`HMAC(secret, role)`, set by the
sync DDL and re-derived at connect time, paired with scram-sha-256); the server
does NOT hold CREATEROLE, it emits the exact DDL to sync roles which a cron job
applies out of band; admin routes live on the main listener gated to
`admin_user`.

## 1. Goal and scope

- The server records a database role when a user is added and marks it for
  removal when the user is removed, both through admin routes, and emits the DDL
  that makes login_role RLS work without a human composing it per user.
- Pool parameters are set in config (`[database]`, `[roles]`), not at runtime.
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
  role with a per-role password derived from a master secret (`HMAC(secret,
  role)`, set by the sync DDL and re-derived at connect time, paired with
  scram-sha-256). Client cert plus `pg_ident` is impractical for dynamically
  created roles (a `pg_ident` line per role plus a reload on every creation), so
  it is not used.
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

The only persisted state is on the user row: `pathql_auth_users` gains `db_role`
(the managed role name), so removal is unambiguous and never reconstructed from
user input. Pool parameters are not persisted; they come from config.ini on
every boot. There is no `pathql_pool_settings` table.

## 6. Admin routes

All gated to a dedicated `admin_user` principal (fail closed when empty), the
same model as the metrics user, plus audit logging with the request id and the
resolved admin identity, and the existing rate limits. TLS is expected.

User lifecycle:

- `POST /admin/users` create a user, record its pending role.
- `DELETE /admin/users/{id}` remove a user, evict its pool, mark its role for the
  next sync to drop.

Role sync:

- `GET /admin/roles/sync` emit the DDL that reconciles the database roles with
  the users table, for an operator or cron job to apply.

There are no pool-configuration routes: pool sizing is config-only (see the note
at the top of this document).

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
  the configured pool parameters from `[database]`.
- A global weighted semaphore sized at `max_total_backends`. Every checkout
  acquires from it before using a connection. PostgreSQL has no cross-pool limit
  and `database/sql` has no global cap, so this semaphore is what bounds the total
  number of backends regardless of how many role pools exist or what per-pool
  values are set. It is the hard ceiling.
- `warm_pool_limit` caps how many role pools keep a warm idle connection; an LRU
  evicts idle connections from pools beyond the limit. The pool struct can remain
  with zero open connections.

## 9. Pool parameters

- All from config, fixed for the process lifetime: the per-pool defaults
  (`max_open_conns`, `max_idle_conns`, `conn_max_lifetime_ms`,
  `conn_max_idle_time_ms`) under `[database]`, plus the `max_total_backends` and
  `warm_pool_limit` guardrails. There is no runtime mutation and no per-user
  override.
- The global semaphore at `max_total_backends` is the hard backstop on total
  backends regardless of the per-pool values.

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

[security]
identity_kind = "login_role"  # select the per-role model (default is "none")
admin_user    = "admin"       # principal allowed on /admin/*; empty disables them

[roles]
base_dsn        = "host=... dbname=pathql sslmode=disable"  # no user=
baseline_role   = "pathql_auth"
prefix          = "pathql_r_"
reader_role     = "pathql_readers"
warm_pool_limit = 64          # config only
password_secret = "${PATHQL_ROLE_SECRET}"  # derives each role's connection password
```

## 12. Security rails

- The server holds no CREATEROLE: it only reads the catalog to emit the sync
  DDL, which a privileged out-of-band role (operator or cron) applies. The query
  and reader roles are never CREATEROLE and never superuser.
- Managed roles are `LOGIN NOSUPERUSER NOCREATEROLE`, members only of the reader
  role, never of each other (the pivot risk).
- LOGIN roles are only safe because `pg_hba` restricts who may connect as them
  (scram-sha-256 with the derived per-role password); the plan documents that
  pg_hba must not expose them more widely.
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
  role; the global ceiling holds even with absurd per-pool values; reconcile
  creates a missing role and reports an orphan without dropping it.

## 14. Build order

0. (Prerequisite) login_role connection layer: principal to role mapping,
   per-role authentication, per-role pools, `current_user` policies.
1. Provisioner connection, name derivation, prefix and managed guards.
2. Role lifecycle SQL behind a small `roles` package, tested against throwaway
   PostgreSQL.
3. Admin routes and `admin_user` gating, audit and rate limiting.
4. Pool manager: global semaphore, warm-pool LRU, per-pool stats (read-only).
5. Reconcile, report-only, wired into startup.
6. Docs (README operations, config, hardening notes) and demo wiring.

## 15. Open decisions

1. login_role prerequisite: plan and build it first as phase 0, or assume the
   per-role password plus per-role pool layer is already in place.
2. Provisioner credential: the server holds a CREATEROLE credential as planned,
   or the DDL is delegated to an admin-run step or rls-polyfill so the server
   never holds CREATEROLE (smaller blast radius, but no fully self-service admin
   route).
3. Admin route exposure: gate on `admin_user` on the main listener, or bind
   `/admin/*` to a separate or loopback listener for network isolation.

Resolved since the first revision: pool parameters are config-only (no runtime
`/admin/pool` routes and no per-user overrides), and the server emits role-sync
DDL rather than holding a CREATEROLE provisioner credential.
