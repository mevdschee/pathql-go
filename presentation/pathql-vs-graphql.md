---
marp: true
theme: default
class: invert
paginate: true
title: PathQL vs GraphQL
author: Maurits van der Schee
---

<!-- _class: lead -->

# PathQL

### SQL in, nested JSON out

The GraphQL alternative that is just SQL

Maurits van der Schee · [pathql.org](https://pathql.org/)

---

## The whole idea

- POST a SQL query, get nested JSON back
- Nesting is inferred from foreign keys (or PATH hints)
- Not a new language, not an ORM: you still write SQL
- No resolvers. No schema files. No codegen.
- A small Go binary in front of your database

---

## GraphQL: the stack you maintain

- SDL schema types for every entity
- A resolver function for every field
- DataLoaders to dodge N+1
- A gateway to run it (Apollo, federation)
- Codegen and client tooling on top

---

## Where GraphQL hurts

- N+1 queries by default
- Cannot express SQL: GROUP BY, windows, CTEs
- Authorization hand-written per resolver
- Query-complexity DoS you must defend against
- Three schemas drift: SDL, resolvers, database

---

## One endpoint: POST /pathql

```json
{
  "query": "SELECT id, content FROM posts WHERE id = :id",
  "params": { "id": 1 }
}
```

Response: `[{ "id": 1, "content": "blog started" }]`

---

## Automatic nesting from foreign keys

```sql
SELECT p.id, c.id, c.message
FROM posts p LEFT JOIN comments c ON c.post_id = p.id
```

The engine reads the FK and groups comments under each post.

---

## One query, nested JSON

```json
[{
  "p": { "id": 1 },
  "c": [{ "id": 1, "message": "great!" }, { "id": 2, "message": "nice!" }]
}]
```

No join logic in app code. One database round trip.

---

## The N+1 problem, gone

- GraphQL: a `Post.comments` resolver fires once per post
- Fix is DataLoader batching: more code, more bugs
- PathQL: one JOIN, one query, planned by the database
- N+1 is impossible by construction

---

## It is just SQL

```sql
SELECT c.name, count(p.id) AS post_count
FROM posts p JOIN categories c ON p.category_id = c.id
GROUP BY c.name
```

Aggregates, GROUP BY, window functions, CTEs: all free.

---

## "But sending SQL from clients is insane!"

- Correct: raw SQL to a database would be reckless
- PathQL's answer: the database is the boundary
- Read-only, least privilege, RLS, cost limits
- The next three slides show why it is safe

---

## Safe by construction (1 of 3)

- The role is granted SELECT only: no writes, no DDL
- Every query runs in a READ ONLY transaction
- SQL gate: one statement, no system catalogs
- Dangerous functions revoked (pg_sleep, pg_read_file)

---

## Unforgeable tenant isolation (2 of 3)

- The server connects as the caller's own DB role
- RLS policies key on `current_user`
- No CTE or function can forge another identity
- The database enforces it, not your application code
- GraphQL: every field needs a hand-written check

---

## Abuse protection built in (3 of 3)

- EXPLAIN cost ceiling rejects expensive queries first
- The query-complexity problem, solved by the planner
- Per-IP rate limits and concurrency caps
- Body and response size caps, statement timeouts

---

## Discover and observe

- `GET /schema` returns DBML of what you can read
- Scoped by RLS: you see only what you can query
- `GET /metrics` ranks the costliest queries
- Like introspection, but free from the database

---

## Writes, opt-in

- Off by default; the read path stays read-only
- `INSERT/UPDATE/DELETE ... RETURNING` returns JSON
- RLS `WITH CHECK` blocks cross-tenant writes
- A blast-radius cap limits affected rows

---

## Head to head

|               | GraphQL           | PathQL                |
| ------------- | ----------------- | --------------------- |
| Expose data   | SDL + resolvers   | send SQL              |
| N+1           | needs DataLoader  | impossible            |
| Authorization | per resolver      | DB row-level security |
| Infra         | gateway + codegen | one Go binary         |

---

## When GraphQL still fits

- An API-first product with many consumer teams
- Federating many heterogeneous or non-SQL backends
- A curated public contract, decoupled from storage
- It is a trade-off, not an absolute win
- PathQL's mitigation: expose SQL views as the contract

---

## Why PathQL wins

- Less code: no resolvers, no schema duplication
- Faster: one planned query, no N+1
- Safer: RLS, least privilege, and cost limits
- Simpler: SQL you already know, one binary

---

<!-- _class: lead -->

## Try it

`docker compose up` in `examples/demo`

POST SQL to `/pathql`, get nested JSON

[pathql.org](https://pathql.org/) · github.com/mevdschee/pathsqlx
