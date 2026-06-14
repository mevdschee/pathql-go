# pathql-server demo (simple, no-RLS)

A one-command demo of the simplest pathql-server setup: PostgreSQL seeded with
sample data and auth, plus the server connecting as a single shared role. It
reproduces the example queries from the [top-level README](../../README.md) and
shows API-key and Basic authentication.

Every request runs as the same database role (`pathql_app`), so there is **no
per-user isolation**. That is the point of this mode: minimal setup for
development or a single trusted tenant. For row-level security where each user
only sees their own rows, see the sibling [examples/login-role](../login-role/)
demo.

This is a demo, not a hardened deployment: it uses plaintext HTTP on localhost
and fixed demo credentials.

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

- `localhost:8000` - the API: `POST /pathql` and `GET /metrics`
- `localhost:5433` - the demo Postgres (only to poke at it directly; the server
  talks to the database over the compose network)

The demo credentials are:

- API key **`pql_demo_alice_8c1f2a9b4d6e7035`** (app_user `alice`)
- Basic login **`alice` / `alice-password`**
- metrics API key **`pql_metrics_3f9a1c7d5e2b8460`** (app_user `metrics`, allowed
  only on `/metrics`)

Tear everything down, including the database volume, with:

```sh
docker compose down -v
```

## The flow

### a. A simple query

```sh
curl -s localhost:8000/pathql \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT id, content FROM posts WHERE id = :id","params":{"id":1}}'
```

```json
[{ "id": 1, "content": "blog started" }]
```

Basic auth works the same way:

```sh
curl -s -u alice:alice-password localhost:8000/pathql \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT id FROM posts ORDER BY id"}'
```

### b. Automatic nesting: posts with their comments

```sh
curl -s localhost:8000/pathql \
  -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT p.id, c.id, c.message FROM posts p LEFT JOIN comments c ON c.post_id = p.id ORDER BY p.id, c.id"}'
```

```json
[
  { "p": { "id": 1 }, "c": [{ "id": 1, "message": "great!" }, { "id": 2, "message": "nice!" }] },
  { "p": { "id": 2 }, "c": [{ "id": 3, "message": "interesting" }, { "id": 4, "message": "cool" }] }
]
```

pathsqlx detected the one-to-many relationship from the foreign key and grouped
the comments under each post. See the [top-level README](../../README.md) for
more query and PATH-hint examples.

### c. metrics is gated to its own principal

`alice` is a normal user, so `/metrics` is forbidden:

```sh
curl -i -s localhost:8000/metrics -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035'
# 403
```

The metrics key works:

```sh
curl -s localhost:8000/metrics -H 'X-API-Key: pql_metrics_3f9a1c7d5e2b8460'
```

## How it works

1. The server reads `config.ini`, which sets `dsn` to connect as `pathql_app`.
   With no `identity_kind` set it defaults to `none`: one shared pool, no RLS.
2. Each request is authenticated against the auth tables (API key or Basic).
3. The query runs on the shared connection inside a read-only transaction and
   the nested JSON is returned. Every caller sees the same data; the database
   does no per-user filtering.

## Teardown

```sh
docker compose down -v
```
