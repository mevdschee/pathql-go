# Knowledge exchange: PathQL vs GraphQL

Companion notes for presenting `pathql-vs-graphql.md` (Marp deck, ~20 slides).

## Summary

PathQL is a small idea: you write a normal SQL query and get nested JSON back,
with the nesting inferred from table aliases and foreign keys. `pathql-server`
turns that into an HTTP endpoint (`POST /pathql`) that can safely run untrusted
SQL by making the database the authorization boundary: a least-privilege
read-only role, PostgreSQL row-level security keyed on `current_user`, and a set
of pre-execution guards (SQL gate, EXPLAIN cost ceiling, rate limits).

This session walks the deck, runs a live demo against the bundled
`examples/demo`, and compares the approach with GraphQL. The honest position
(shared by the author's blog posts) is that it is a trade-off, not an absolute
win: PathQL removes the resolver layer, the N+1 hazard, and most output-shaping
code for teams doing relational data access, while GraphQL keeps the edge for an
API-first product serving many heterogeneous consumer teams.

## Goal

By the end, attendees should be able to:

- Explain the PathQL model: SQL in, nested JSON out, nesting from foreign keys.
- Say why there are no resolvers and why N+1 is impossible by construction.
- Describe the security model: database-as-boundary, unforgeable RLS via
  `current_user`, least privilege, and the EXPLAIN cost ceiling.
- Decide when PathQL fits their problem and when GraphQL is the better tool.
- Run the demo themselves and POST a query.

## Audience and prerequisites

- Backend and full-stack engineers who have used REST and/or GraphQL.
- Comfortable reading SQL (joins, GROUP BY) and a `curl` command.
- No PathQL experience assumed.

## Agenda (45 minutes)

- 5 min: the problem (rows vs nested JSON, the GraphQL stack you maintain)
- 10 min: the PathQL model and live nesting demo
- 10 min: "isn't sending SQL dangerous?" and the security model
- 5 min: head to head and operational simplicity
- 5 min: honest trade-offs, when GraphQL still fits
- 10 min: Q&A and free-form demo

## Preparation

### For the presenter

1. Render the deck. Either the VS Code "Marp for VS Code" extension (live
   preview, export), or the CLI:
   ```sh
   npx @marp-team/marp-cli presentation/pathql-vs-graphql.md -o slides.html
   # or: ... --pdf   /   --pptx
   ```
2. Start the demo so the live curls work:
   ```sh
   cd examples/demo && docker compose up --build
   ```
   It is ready when the server logs its listen address (`:8000`).
3. Dry-run every demo command below once; keep them in a scratch file to paste.
4. Skim the two source posts so the framing in your words matches the author's:
   "safe SQL to JSON" (the server and its security model) and "Nested JSON
   queries" (the core idea and the GraphQL trade-off).
5. Re-read README sections: Row-level security, SQL gate, Cost ceiling, and the
   `examples/rls_policy.sql` policy, so you can answer security questions.
6. Have two terminals ready: one running the demo, one for live curls.

### For attendees (optional, send beforehand)

- Install Docker with the Compose v2 plugin if they want to follow along.
- Read the README "Quick start" (about 5 minutes).
- Bring one endpoint from their own work that returns nested JSON, to discuss.

## Live demo script

Demo credentials (from `examples/demo`): API key `pql_demo_alice_8c1f2a9b4d6e7035`,
metrics key `pql_metrics_3f9a1c7d5e2b8460`.

1. Simple query, flat array:
   ```sh
   curl -s localhost:8000/pathql -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
     -H 'Content-Type: application/json' \
     -d '{"query":"SELECT id, content FROM posts WHERE id = :id","params":{"id":1}}'
   ```
2. The headline: automatic nesting from a foreign key:
   ```sh
   curl -s localhost:8000/pathql -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
     -H 'Content-Type: application/json' \
     -d '{"query":"SELECT p.id, c.id, c.message FROM posts p LEFT JOIN comments c ON c.post_id = p.id ORDER BY p.id, c.id"}'
   ```
3. "It is just SQL": a GROUP BY aggregate in one request:
   ```sh
   curl -s localhost:8000/pathql -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035' \
     -H 'Content-Type: application/json' \
     -d '{"query":"SELECT categories.name AS name, count(posts.id) AS post_count FROM posts, categories WHERE posts.category_id = categories.id GROUP BY categories.name"}'
   ```
4. Authorization lives in the server: `alice` is refused on `/metrics` (403),
   the metrics key is allowed:
   ```sh
   curl -i -s localhost:8000/metrics -H 'X-API-Key: pql_demo_alice_8c1f2a9b4d6e7035'   # 403
   curl -s    localhost:8000/metrics -H 'X-API-Key: pql_metrics_3f9a1c7d5e2b8460'
   ```

For the unforgeable RLS story, point at `examples/login-role` and
`examples/rls_policy.sql` rather than running it live; it needs per-role
provisioning and is better shown as code than demoed under time pressure.

## Talking points and anticipated questions

- "Isn't sending SQL from a client reckless?" Yes, on a bare connection. The
  whole server exists to make the database the boundary: read-only transactions,
  a SELECT-only role, RLS on `current_user`, the SQL gate, and the cost ceiling.
- "How is this different from PostgREST or Hasura?" PostgREST exposes tables as
  REST routes; Hasura is GraphQL over Postgres. PathQL is more direct: you send
  the SQL statement itself and get nesting from foreign keys, with no generated
  query layer in between.
- "Doesn't this couple clients to the database schema?" It can. The mitigation
  is to expose SQL views as the stable contract, which you can version and
  reshape without moving physical tables.
- "What about databases other than PostgreSQL?" The core nesting works on
  MariaDB too; RLS, schema reflection, and the EXPLAIN cost ceiling are
  PostgreSQL-only.
- "Performance?" One planned query per request. The database planner does the
  optimizing (indexes, EXPLAIN), instead of app-layer resolver orchestration.
- Framing to land: this is a deep module in Ousterhout's sense. The interface
  stayed one sentence ("send SQL, get nested JSON") while the complexity went
  into the database boundary and the layers in front of it.

## Follow-up resources

- Deck: `presentation/pathql-vs-graphql.md`
- README: row-level security, SQL gate, cost ceiling, writes
- `examples/demo` and `examples/login-role` (runnable)
- `examples/rls_policy.sql` (the policy and grants)
- Posts: "PathQL: Nested JSON queries" and "PathQL server: safe SQL to JSON"
- Code: github.com/mevdschee/pathql-server and github.com/mevdschee/pathsqlx
