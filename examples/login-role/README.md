# pathql-server demo

A one-command demo of pathql-server. Each user maps to its own PostgreSQL role,
the server opens its database connection AS that role, and row-level security
keys on `current_user`. Because `current_user` is the role the connection
authenticated as, a query cannot forge it: the identity boundary lives in the
database, not in anything the request can set.

This is a demo, not a hardened deployment: it uses plaintext HTTP on localhost
and fixed demo credentials. The database connections do use real per-role
passwords (SCRAM), derived from a `password_secret` that is checked into the
example for convenience; in production load that secret from the environment.

## How identity reaches RLS

The server never runs caller queries on a shared application role. It connects
as the caller's own per-user role and lets PostgreSQL enforce identity:

- connects as the caller's own per-user role (`pathql_r_<id>`)
- RLS keys on `current_user`, the role the connection authenticated as
- a query cannot change `current_user`, so identity cannot be forged in SQL
- per-user roles are created out of band from the DDL the server emits at
  `GET /admin/roles/sync`; the server itself never holds CREATEROLE

A nice property: even a single statement that tries to change the role is
rejected by the database, so identity holds without the server having to defend
a session variable.

## Prerequisites

Docker with the Compose v2 plugin (`docker compose version` should work). On
installs that only ship the engine, add it (Debian/Ubuntu:
`apt install docker-compose-v2`).

## Run it

From this directory:

```sh
docker compose up --build
```

The first run builds the server image and seeds the database; it is ready once
the server logs its listen address. Two ports are exposed:

- `localhost:8000` - the API: `POST /pathql`, `GET /metrics`, and the
  `/admin/*` routes
- `localhost:5434` - the demo Postgres (only to poke at it directly, and to
  apply the role-sync DDL; the server talks to the database over the compose
  network)

The admin bootstrap API key is **`adminkey_0001`** (app_user `admin`). It is
allowed only on `/admin/*`; it cannot run `/pathql` or read `/metrics`.

Tear everything down, including the database volume, with:

```sh
docker compose down -v
```

## The flow

The key idea: **the server never runs role DDL.** It holds no `CREATEROLE`. When
you add or remove a user it records the change in the auth tables and emits the
exact DDL needed to make the login roles match. An operator (or a cron job)
applies that DDL out of band as a privileged role. Below we play the operator by
piping the DDL into `psql`.

### a. Add alice and bob

```sh
curl -s localhost:8000/admin/users \
  -H 'X-API-Key: adminkey_0001' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","generate_api_key":true}'
```

```sh
curl -s localhost:8000/admin/users \
  -H 'X-API-Key: adminkey_0001' \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","generate_api_key":true}'
```

Each response includes the new user `id`, the pending `db_role`
(`pathql_r_2` for alice, `pathql_r_3` for bob), and a one-time `api_key`. **Save
the two `api_key` values**; they are shown only once. We will call them
`<ALICE_KEY>` and `<BOB_KEY>` below.

At this point alice and bob exist in the auth tables but their database roles do
not exist yet, so they cannot query. That is expected: role creation lags user
creation until the sync runs.

### b. Sync the roles (operator step)

Ask the server for the DDL needed to reconcile roles with users:

```sh
curl -s localhost:8000/admin/roles/sync -H 'X-API-Key: adminkey_0001'
```

The response lists the `ddl` lines: a `CREATE ROLE ... LOGIN NOSUPERUSER
NOCREATEROLE ... PASSWORD '...'` (the derived per-role password) and a `GRANT
pathql_readers` for each of alice and bob. Apply them as the superuser:

```sh
curl -s localhost:8000/admin/roles/sync -H 'X-API-Key: adminkey_0001' \
  | python3 -c 'import sys,json; print("\n".join(json.load(sys.stdin)["ddl"]))' \
  | docker compose exec -T db psql -U postgres -d pathql
```

(Any way of extracting the `ddl` array and piping it into psql works; the
`python3` filter above is just convenient.) The server only ever emits DDL for
roles whose name matches the managed prefix `pathql_r_`, and quotes every
identifier.

### c. Query as alice, then as bob

```sh
curl -s localhost:8000/pathql \
  -H 'X-API-Key: <ALICE_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT owner, body FROM documents ORDER BY body"}'
```

```json
[{ "owner": "pathql_r_2", "body": "alice-secret-1" },
 { "owner": "pathql_r_2", "body": "alice-secret-2" }]
```

The same query as bob returns only bob's row:

```sh
curl -s localhost:8000/pathql \
  -H 'X-API-Key: <BOB_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT owner, body FROM documents ORDER BY body"}'
```

```json
[{ "owner": "pathql_r_3", "body": "bob-secret" }]
```

Nothing in the query changed. The rows differ because each request runs on a
different database role and the RLS policy compares `owner = current_user`.

### d. Show the identity

```sh
curl -s localhost:8000/pathql \
  -H 'X-API-Key: <ALICE_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT current_user"}'
```

```json
[{ "current_user": "pathql_r_2" }]
```

alice's connection authenticated as `pathql_r_2`. That is the identity RLS uses.

### e. A forge attempt fails

Try to switch roles inside a single statement:

```sh
curl -i -s localhost:8000/pathql \
  -H 'X-API-Key: <ALICE_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT set_config('\''role'\'','\''pathql_r_3'\'',true)"}'
```

This returns `500`: PostgreSQL rejects it with `permission denied to set role
"pathql_r_3"`. The managed roles are not members of each other, so alice's role
cannot become bob's, even for one statement. Identity cannot be forged from query
text.

### f. alice is forbidden on /metrics and /admin

alice is a normal user, not the admin or metrics principal:

```sh
curl -i -s localhost:8000/metrics -H 'X-API-Key: <ALICE_KEY>'
```

```sh
curl -i -s localhost:8000/admin/users -H 'X-API-Key: <ALICE_KEY>'
```

Both return `403`.

### g. Delete alice and drop her role

```sh
curl -s -X DELETE localhost:8000/admin/users/2 -H 'X-API-Key: adminkey_0001'
```

Now the sync emits a `DROP ROLE IF EXISTS "pathql_r_2"` for the role whose user
is gone:

```sh
curl -s localhost:8000/admin/roles/sync -H 'X-API-Key: adminkey_0001'
```

Apply it the same way as before:

```sh
curl -s localhost:8000/admin/roles/sync -H 'X-API-Key: adminkey_0001' \
  | python3 -c 'import sys,json; print("\n".join(json.load(sys.stdin)["ddl"]))' \
  | docker compose exec -T db psql -U postgres -d pathql
```

After the role is dropped, alice's old API key returns `401`: the user row is
gone, so there is nothing to authenticate.

## How it works

1. A user is added through `/admin/users`. The server stores the user and its
   derived role name (`prefix` + `id`) but does not create the role; it holds no
   `CREATEROLE`.
2. `/admin/roles/sync` reads `pg_roles` and the auth tables over the baseline
   connection and emits an idempotent DDL script: `CREATE ROLE` for users with no
   role, `GRANT <reader_role>` for roles missing read access, and `DROP ROLE IF
   EXISTS` for managed-prefixed roles whose user is gone.
3. An operator or cron job applies that DDL as a privileged role. This is the
   only place role DDL ever runs.
4. On each request the server resolves the caller, opens (or reuses) a connection
   that authenticates as that caller's role with the role's derived password, and
   runs the query. RLS filters by `current_user`.

## Security notes

- **Each role authenticates with a password (SCRAM).** This demo sets
  `POSTGRES_HOST_AUTH_METHOD=scram-sha-256`, so every connection needs a real
  password. The server never stores per-role secrets: each role's password is
  derived as `HMAC-SHA256(password_secret, role)`, set on the role by the
  role-sync DDL (and on the baseline role by initdb), and re-derived at connect
  time. Keep `password_secret` itself out of source control in production (load
  it from `${ENV}`).
- **Managed roles are tightly scoped.** They are `LOGIN`, `NOSUPERUSER`,
  `NOCREATEROLE`, members of `pathql_readers`, and never members of one another.
  So a managed role can read its own rows and nothing else, and cannot become
  another user's role.
- **The server holds no CREATEROLE.** It only reads the catalog to compute the
  diff and emits DDL as text; an out-of-band privileged role applies it. This
  keeps the server's blast radius small even if it is compromised.
- `FORCE ROW LEVEL SECURITY` on `documents` makes the policy apply even to the
  table owner, so there is no owner bypass.
- The server logs one line per request (`verbose = true` in `config.ini`); watch
  it with `docker compose logs -f server`.

## Teardown

```sh
docker compose down -v
```
