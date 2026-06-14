# pathql-server demo

A one-command demo: PostgreSQL seeded with auth and sample data, plus the
pathql-server built from this repo. It reproduces the example queries from the
[top-level README](../../README.md) and shows authentication and row-level
security working end to end.

This is a demo, not a hardened deployment: it uses plaintext HTTP on localhost
and fixed demo credentials. For production settings see the
[main README](../../README.md) and [../rls_policy.sql](../rls_policy.sql).

## Prerequisites

Docker with the Compose v2 plugin (`docker compose version` should work). On
installs that only ship the engine, add it (Debian/Ubuntu:
`apt install docker-compose-v2`).

## Run it

From this directory:

```sh
docker compose up --build
```

The first run builds the server image and seeds the database; it's ready once
you see the server log its listen address. Two ports are exposed:

- `localhost:8000` - the API: `POST /pathql` and `GET /metrics` (metrics is
  gated to the `metrics` user)
- `localhost:5433` - the demo Postgres (only to poke at it directly; the server
  talks to the database over the compose network)

On startup the server runs its hardening self-check against the demo role and
logs one warning, that `posts`, `comments` and `categories` have no row-level
security. That is intentional here (they are public sample data); the
`documents` table does have RLS. Watch it with `docker compose logs server`.

Tear everything down, including the database volume, with:

```sh
docker compose down -v
```

## What gets seeded

Content tables (`categories`, `posts`, `comments`) with the exact rows used in
the main README's examples, plus a `documents` table protected by row-level
security. Three users:

| user    | password         | API key                            | can do                          |
|---------|------------------|------------------------------------|---------------------------------|
| alice   | `alice-password` | `pql_demo_alice_8c1f2a9b4d6e7035`  | query; sees her 2 `documents`   |
| bob     | `bob-password`   | (none, Basic only)                 | query; sees his 1 `document`    |
| metrics | (none)           | `pql_metrics_3f9a1c7d5e2b8460`     | read `/metrics` only            |

The `metrics` user has `app_user = 'metrics'` (the configured `metrics_user`), so
the server lets it read `/metrics` and forbids it on `/pathql`. Conversely alice
and bob can query but get `403` on `/metrics`.

## Try it

All requests need `Content-Type: application/json` and an authenticated
identity. Alice authenticates with her API key; bob with HTTP Basic.

### Simple query (flat array)

```sh
curl -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -d '{"query":"SELECT id, content FROM posts WHERE id = :id","params":{"id":1}}'
```

```json
[{ "id": 1, "content": "blog started" }]
```

### Join with automatic nesting (posts with comments)

pathsqlx reads the foreign keys to detect the one-to-many relationship and nests
each post's comments under a sibling `c` array:

```sh
curl -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -d '{"query":"SELECT p.id, c.id, c.message FROM posts p LEFT JOIN comments c ON c.post_id = p.id WHERE p.id <= 2 ORDER BY p.id, c.id","params":{}}'
```

```json
[
  { "p": { "id": 1 }, "c": [{ "id": 1, "message": "great!" }, { "id": 2, "message": "nice!" }] },
  { "p": { "id": 2 }, "c": [{ "id": 3, "message": "interesting" }, { "id": 4, "message": "cool" }] }
]
```

### PATH hint (nested object root)

```sh
curl -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -d '{"query":"SELECT posts.id, comments.id FROM posts LEFT JOIN comments ON post_id = posts.id WHERE posts.id <= 2 ORDER BY posts.id, comments.id","params":{},"paths":{"posts":"$.posts"}}'
```

```json
{ "posts": [ { "id": 1, "comments": [{ "id": 1 }, { "id": 2 }] }, { "id": 2, "comments": [{ "id": 3 }, { "id": 4 }] } ] }
```

### Row-level security: alice sees only her documents

```sh
curl -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -d '{"query":"SELECT id, body FROM documents ORDER BY id","params":{}}'
```

```json
[{ "id": 1, "body": "alice private note one" }, { "id": 2, "body": "alice private note two" }]
```

### Row-level security: bob (HTTP Basic) sees only his

The same query returns different rows for a different identity. Nothing in the
query changes; the policy filters by the bound `app.user`.

```sh
curl -s -u bob:bob-password localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT id, body FROM documents ORDER BY id","params":{}}'
```

```json
[{ "id": 3, "body": "bob private note" }]
```

### No credentials -> 401

```sh
curl -i -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT 1 AS one"}'
```

### Stacked statement -> 400 (blocked before it reaches the database)

```sh
curl -i -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -d '{"query":"SELECT 1; DROP TABLE posts"}'
```

### Metrics: only the metrics user may read them

The `metrics` user reads `/metrics` with its API key (200):

```sh
curl -s localhost:8000/metrics -H 'X-API-Key: pql_metrics_3f9a1c7d5e2b8460'
```

alice (a normal user) is forbidden on `/metrics` (403):

```sh
curl -i -s localhost:8000/metrics -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035'
```

and the metrics user is forbidden on `/pathql` (403):

```sh
curl -i -s localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: pql_metrics_3f9a1c7d5e2b8460' \
  -d '{"query":"SELECT 1 AS one"}'
```

## Notes

- The server logs one line per request (`verbose = true` in `config.ini`); watch
  it with `docker compose logs -f server`.
- `config.ini` is bind-mounted read-only, so the server prints a one-line
  startup warning that the file is group/other-readable. That's expected for the
  demo; in production keep it `chmod 600`.
- HTTP Basic is sent in cleartext here because the demo is plaintext localhost.
  Only use Basic over TLS in real deployments.
