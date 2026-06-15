# Write support plan

This document plans optional write support for pathql-server. Today the server
is read-only: every query runs in a `READ ONLY` transaction, the SQL gate (when
on) accepts only `SELECT`/`WITH`/`TABLE`/`VALUES`, the example grants are
`SELECT` only, and the startup hardening check treats any write privilege as a
critical finding. Read-only is not one flag; it is a property asserted
independently in several layers. Adding writes means re-doing the hardening
story for a write surface, not flipping a switch.

The guiding principle is to keep the project's identity ("send SQL, get JSON")
and its strongest property (the database, not the application, is the
unforgeable security boundary). Writes are added as an opt-in capability that is
gated as hard as reads, not as a relaxation of the existing model.

## Goals

- Allow `INSERT`, `UPDATE`, and `DELETE` (including data-modifying `WITH` CTEs)
  through the existing `POST /pathql` endpoint, off by default.
- Return either the written rows as JSON (when the statement has `RETURNING`) or
  an affected-row count (when it does not).
- Keep reads in a read-only transaction even when writes are enabled, so
  enabling writes never weakens the read path.
- Make per-tenant write isolation a database guarantee (RLS `WITH CHECK`), the
  same way read isolation is a database guarantee today.
- Add a write-side analogue of the cost ceiling: a blast-radius cap so an
  unbounded `UPDATE`/`DELETE` is refused.

## Non-goals

- No structured CRUD endpoint (`/records/{table}`-style). The SQL stays the
  interface; we do not reimplement php-crud-api.
- No DDL (`CREATE`/`ALTER`/`DROP`), no `TRUNCATE`, no `COPY ... FROM`, no
  `MERGE` (can be revisited later). These stay rejected.
- No multi-statement transactions across requests. One request is still one
  statement in one transaction.
- No new write support for the `none` identity mode beyond the trusted
  single-tenant case (see Security model).

## Why read-only is load-bearing (the layers to change)

| Layer | File | Today | Change |
|---|---|---|---|
| Transaction mode | `internal/db/executor.go:153` | always `ReadOnly` from config | choose per request: reads read-only, writes read-write |
| SQL gate | `internal/sqlgate/sqlgate.go:51` | `readStarters` only | classify read vs write vs reject |
| DB grants | `examples/rls_policy.sql:37` | `SELECT` only, `REVOKE INSERT/UPDATE/DELETE` | optional write grants + `WITH CHECK` policies |
| Hardening check | `internal/db/hardening.go:86` | write grant is Critical | when writes enabled, expected; missing write policy becomes the new Critical |
| Cost ceiling | `internal/db/executor.go:94` | EXPLAIN read estimate | reuse for write blast-radius estimate |
| Handler wiring | `pathql.go:446` | passes `cfg.Security.ReadOnly` | route by statement class, pick read vs write path |
| Config | `internal/config/config.go:52,89` | `read_only` bool, `sql_gate` off/on | add `writes` toggle, extend gate mode |
| Docs | `README.md`, `config.ini`, `openapi.yaml` | read-only described | document the write surface |

## Key design decisions

### 1. One endpoint, classify per request

`POST /pathql` keeps taking a single statement. The server classifies it from
its leading keyword (the gate's tokenizer already does exactly this) into one
of three outcomes:

- **read** (`SELECT`/`WITH`-that-only-reads/`TABLE`/`VALUES`): runs in a
  `READ ONLY` transaction, exactly as today.
- **write** (`INSERT`/`UPDATE`/`DELETE`, or `WITH` whose final statement
  modifies data): runs in a read-write transaction, allowed only when writes
  are enabled.
- **rejected** (everything else: DDL, `TRUNCATE`, `COPY`, `SET`, `SHOW`,
  `EXPLAIN`, `CALL`, `DO`, stacked statements, catalog access).

This keeps reads hardened even with writes on, and the classifier is the
natural extension of the existing `readStarters` map.

A subtlety: a `WITH` query can wrap a data-modifying CTE
(`WITH x AS (DELETE ... RETURNING ...) SELECT ...`). The lightweight tokenizer
cannot prove a `WITH` is read-only, so the conservative rule is: a `WITH`
statement is classified **write** whenever writes are enabled (it runs in a
read-write transaction, where a read-only `WITH` is still perfectly valid), and
**read** when writes are disabled (matching today, where the read-only
transaction is the backstop that rejects a modifying CTE). This preserves the
current guarantee and avoids a parser dependency in the gate.

### 2. Config surface: a single `writes` toggle

Add `[security] writes = "off" | "on"`, default `"off"`. It is the master
switch. The existing `read_only` bool and `sql_gate` keep working:

- `writes = "off"` (default): identical to today. Reads run read-only; the gate
  (if on) rejects write statements at the edge.
- `writes = "on"`: write statements are accepted, classified, and run in a
  read-write transaction. Reads still run read-only.

`read_only` becomes a derived, internal notion (per-request, set by the
classifier) rather than a single global. The top-level `read_only` config key is
kept for backward compatibility but, when `writes = "on"`, it no longer forces
the read path's mode onto writes. Validation rejects the contradictory combo
`read_only = true` together with `writes = "on"` with a clear message, so the
operator picks one model explicitly.

The SQL gate gains the write vocabulary automatically from the classifier; we do
not add a separate `sql_gate = "write"` mode. The gate's job stays "reject what
is never allowed" (catalogs, stacked statements, non-DML non-read statement
types); the `writes` toggle decides whether the write class is admitted.

### 3. Return shape: rows when asked, count otherwise

- Statement **has `RETURNING`**: run it through `pathsqlx.PathQueryTx` and return
  the written rows as JSON, subject to `max_response_bytes`. pathsqlx infers
  nesting from a `SELECT ... FROM` shape, so it does not auto-nest a write
  statement: the `RETURNING` columns come back under their bare names (a flat
  array of objects). To shape a write response, the caller supplies `paths`
  hints, typically `{"$": "$"}` or a table path, exactly as for a read. No change
  to pathsqlx is made.
- Statement **has no `RETURNING`**: do not go through pathsqlx (it would return
  an empty array). Run `tx.ExecContext`, read `RowsAffected`, and return
  `{"affected": N}`.

`RETURNING` is detected by scanning the gate's token stream for a top-level
`returning` word, so a `returning` inside a string literal or comment does not
trigger the rows path.

**Driver caveat.** PostgreSQL supports `RETURNING` fully
(`INSERT`/`UPDATE`/`DELETE`). MariaDB supports it only partially (`INSERT` and
`DELETE`, not `UPDATE`). The server's write path, like its other hardening
features, is PostgreSQL-centric, so the `RETURNING` response is primarily a
PostgreSQL feature; on MariaDB it applies to the statement types MariaDB allows.
On any driver, a write without `RETURNING` returns the affected count, and that
path is driver-agnostic (pathsqlx runs through `sqlx` with `Rebind`).

### 4. Blast-radius control

The EXPLAIN cost ceiling already transfers: `EXPLAIN (FORMAT JSON)` on an
`UPDATE`/`DELETE` returns the planner's estimated modified-row count without
executing, so `max_estimated_rows` already bounds a write before it runs. Add a
dedicated, post-execution backstop because estimates can be wrong:

- New config `[limits] max_affected_rows` (0 disables, the default).
- On the write path, after `ExecContext` (or after counting `RETURNING` rows)
  but **before commit**, if the affected count exceeds the cap, roll back and
  return `400` with a generic message (the actual count is logged, not
  returned). Because the check is inside the transaction, an over-cap write
  never commits.

This is the write-side analogue of the read cost ceiling: EXPLAIN stops the
obvious cases up front, the row cap stops the rest before they persist.

## Security model for writes

Writes are only meaningfully safe under `identity_kind = "login_role"`, where
the connected role is the caller's own and RLS keys on `current_user`. Two
modes:

- **`login_role` (recommended for writes).** Per-tenant write isolation is a
  database guarantee. Each writable table needs RLS policies that cover the
  write commands, and crucially a `WITH CHECK` clause so a caller cannot insert
  or update a row attributed to another tenant:
  - `FOR INSERT WITH CHECK (owner = current_user)`
  - `FOR UPDATE USING (owner = current_user) WITH CHECK (owner = current_user)`
  - `FOR DELETE USING (owner = current_user)`
  Without `WITH CHECK`, RLS filters which rows a write can *see* but not which
  rows it can *create or change*, which is a cross-tenant write hole. The plan
  ships these in the example and the hardening check enforces their presence
  (below).
- **`none` (trusted single-tenant only).** The shared connection has no
  per-caller identity, so writes here are fully trusted: every authenticated
  caller writes as the same role with no row-level authorization. Allowed, but
  the docs must state plainly that this is single-tenant only, and the server
  logs a warning at startup when `writes = "on"` with `identity_kind = "none"`.

XSRF protection (already present) matters more once writes exist for
cookie/Basic browser deployments; the docs will point at enabling `xsrf = "on"`
for those.

## Hardening check changes (`internal/db/hardening.go`)

Today a write grant is unconditionally Critical (lines 86-90). With writes:

- When `writes = "off"`: unchanged. A write grant is still Critical, because the
  server promises read-only and a writable role contradicts that.
- When `writes = "on"`: a write grant is expected, so it is no longer Critical
  on its own. Instead add the new check that matters for writes: under
  `login_role` with `startup_checks = "enforce"`, a table the role can write to
  that lacks a `WITH CHECK` policy for the granted command is **Critical** (a
  silent cross-tenant write path). Implement by querying `pg_policy` for
  `polrelid`, `polcmd` (`a`=insert, `w`=update, `*`/`r` as applicable) and
  `polwithcheck` for each table the role holds `INSERT`/`UPDATE` on. A writable
  table with no applicable `WITH CHECK` is the finding.
- Surface a Warning when `writes = "on"` and `identity_kind = "none"` (writes
  with no per-caller authorization).

## Implementation phases

### Phase 1 - SQL gate becomes a classifier
- In `internal/sqlgate`, add `writeStarters` (`insert`, `update`, `delete`) and
  a `Classify(query) (Class, error)` returning `ClassRead`, `ClassWrite`, or an
  error for the rejected cases. Keep the single-statement and no-catalog rules
  for all classes. `Check` is reimplemented in terms of `Classify` to preserve
  existing behavior when writes are off.
- Add a `HasReturning(query) bool` helper using the same tokenizer.
- Tests: every existing gate test still passes; new tests for classification of
  `INSERT/UPDATE/DELETE`, data-modifying `WITH`, `RETURNING` detection (including
  `returning` inside strings/comments/identifiers), and that DDL/`TRUNCATE`/
  `COPY`/stacked statements are still rejected.

### Phase 2 - executor write path (`internal/db/executor.go`)
- Add `RunWrite(ctx, pool, query, params, hints, opts)`:
  - opens a read-write transaction, applies session settings (reuse
    `applySessionSettings`),
  - runs `enforceCostCeiling` (EXPLAIN) as today (now bounding write estimates
    too),
  - if `HasReturning`: `PathQueryTx` to JSON (flat, or shaped by the caller's
    `paths` hints), count the rows for the affected cap; else `ExecContext` and
    read `RowsAffected`,
  - if `max_affected_rows > 0` and the count exceeds it: roll back, return
    `ErrTooManyRowsAffected` (new sentinel, mapped to 400),
  - commit on success.
- `QueryOptions` gains `MaxAffectedRows int64`.
- `RunQuery` is unchanged for reads (still `ReadOnly: true`).
- Tests against the recording fake driver: write path opens a read-write tx,
  applies settings, honors the affected cap (rolls back over the cap), and the
  RETURNING vs count branches.

### Phase 3 - config (`internal/config/config.go`)
- Add `Security.Writes string` (`toml:"writes"`, default `"off"`, validated to
  `off`/`on`).
- Add `Limits.MaxAffectedRows int64` (`toml:"max_affected_rows"`, default 0,
  validated `>= 0`).
- Validation: reject `read_only = true` with `writes = "on"`; reject
  `writes = "on"` with no auth methods under `login_role` (already implied);
  keep `writes = "on"` legal under `none` but flag it for the startup warning.
- Tests for the new fields, defaults, and the rejected combinations.

### Phase 4 - handler wiring (`pathql.go`)
- After auth and gate, call `sqlgate.Classify`. On `ClassWrite` with
  `writes = "off"`, reject with the existing gate-style 400. On `ClassWrite`
  with writes on, call `RunWrite` with `ReadOnly: false` and the affected cap;
  on `ClassRead`, call `RunQuery` with `ReadOnly: true` as today.
- Thread `MaxAffectedRows` from config into `QueryOptions`.
- Map `ErrTooManyRowsAffected` to a generic 400, logging the real count.

### Phase 5 - hardening check (`internal/db/hardening.go`)
- Pass a `writesEnabled bool` into `VerifyHardening`.
- Gate the write-privilege finding on it (Critical only when writes off).
- Add the `WITH CHECK`-coverage check for writable tables under
  `login_role` + `enforce`.
- Add the `none` + writes Warning.
- Tests extend the existing hardening tests (these need the e2e/live-PG path
  where the current hardening tests run).

### Phase 6 - examples, docs, OpenAPI
- `examples/rls_policy.sql`: add a commented "writer" variant with the
  `FOR INSERT/UPDATE/DELETE` policies including `WITH CHECK`, and the matching
  `GRANT INSERT, UPDATE, DELETE` (clearly marked as opt-in, off by default).
- A new `examples/` runnable demo (or a flag on the login-role demo) exercising
  a write with `RETURNING` and a write returning a count.
- `README.md`: a "Writes" section covering the `writes` toggle, the return
  shapes (flat `RETURNING` rows, shaped by `paths` hints, vs the affected count),
  the driver caveat, `max_affected_rows`, the RLS `WITH CHECK` requirement, and
  the single-tenant caveat for `none`.
- `config.ini`: the new keys with comments.
- `openapi.yaml`: document the affected-count response shape alongside the
  existing JSON response.

### Phase 7 - end-to-end tests (`e2e_test.go`)
- Behind the `e2e` tag: seed a writable RLS table with `WITH CHECK` policies,
  then assert: an authorized `INSERT ... RETURNING` returns the row; an
  `INSERT` without `RETURNING` returns `{"affected": 1}`; a cross-tenant
  `INSERT`/`UPDATE` is rejected by RLS; an over-cap `DELETE` is rejected by
  `max_affected_rows` and leaves the table unchanged; and that with
  `writes = "off"` the same write is rejected with 400.

## Decisions

These were the open questions; all are now resolved and the plan above reflects
them.

1. **Config shape: a single `writes = "off"/"on"` toggle.** No per-command
   allowlist and no forced `RETURNING`; classification (`INSERT`/`UPDATE`/
   `DELETE`) is fixed in code, matching the `sql_gate` / `xsrf` style.
2. **`none` mode writes: allowed, with a loud warning.** Writes are permitted
   under `identity_kind = "none"` as a trusted single-tenant case; every caller
   writes as the same role with no per-caller authorization, and the server logs
   a startup warning. Not refused outright.
3. **Affected-row cap: `max_affected_rows = 0` (disabled) by default.** Opt-in,
   matching the cost ceiling (`max_estimated_cost` / `max_estimated_rows` also
   default to 0). No non-zero default is shipped when writes are enabled.
4. **`RETURNING` ergonomics: leave the rows flat, no pathsqlx change.** A write
   with `RETURNING` returns its columns under their bare names (a flat array);
   the caller shapes the response with `paths` hints, exactly as for a read. The
   pathsqlx engine is not modified.
