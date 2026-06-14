-- Demo schema for pathql-server. Runs once, as the postgres superuser, against
-- the `pathql` database on first container boot. Creates:
--   * the least-privilege pathql_app role the server connects as
--   * the auth tables (pathql_auth_users, pathql_auth_api_keys)
--   * sample content tables (categories, posts, comments) matching the examples
--     in ../../README.md
--   * a documents table protected by row-level security, to show RLS isolation
-- Data is loaded separately in 02-seed.sql.

-- pgcrypto gives us digest() for API-key hashes and crypt()/gen_salt() for the
-- bcrypt password hashes the Basic authenticator expects.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The role the server logs in as. NOT a superuser and NOT the owner of the
-- tables below, so row-level security actually applies to it. The password must
-- match PATHQL_DB_PASSWORD in docker-compose.yml.
CREATE ROLE pathql_app LOGIN PASSWORD 'pathql_demo_pw';

-- ---------------------------------------------------------------------------
-- Auth tables (mirrors internal/auth/schema.sql, default pathql_auth_ prefix).
-- ---------------------------------------------------------------------------
CREATE TABLE pathql_auth_users (
  id            bigserial PRIMARY KEY,
  username      text NOT NULL UNIQUE,
  password_hash text,
  app_user      text NOT NULL,
  enabled       boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pathql_auth_api_keys (
  id           bigserial PRIMARY KEY,
  user_id      bigint NOT NULL REFERENCES pathql_auth_users(id),
  key_prefix   text NOT NULL,
  key_hash     bytea NOT NULL,
  name         text,
  expires_at   timestamptz,
  enabled      boolean NOT NULL DEFAULT true,
  last_used_at timestamptz,
  UNIQUE (key_prefix)
);

-- ---------------------------------------------------------------------------
-- Sample content. Foreign keys are required: pathsqlx reads them to detect the
-- one-to-many cardinality that drives automatic JSON nesting.
-- ---------------------------------------------------------------------------
CREATE TABLE categories (
  id   bigint PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE posts (
  id          bigint PRIMARY KEY,
  content     text NOT NULL,
  category_id bigint NOT NULL REFERENCES categories(id)
);

CREATE TABLE comments (
  id      bigint PRIMARY KEY,
  post_id bigint NOT NULL REFERENCES posts(id),
  message text NOT NULL
);

-- ---------------------------------------------------------------------------
-- Row-level security demo. Each row has an owner; the policy only exposes rows
-- whose owner matches the identity the server binds into app.user. An
-- unauthenticated request leaves app.user unset, so current_setting(...) is
-- NULL and no rows match.
-- ---------------------------------------------------------------------------
CREATE TABLE documents (
  id    bigint PRIMARY KEY,
  owner text NOT NULL,
  body  text NOT NULL
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_owner_select
  ON documents
  FOR SELECT
  TO pathql_app
  USING (owner = current_setting('app.user', true));

-- ---------------------------------------------------------------------------
-- Grants. The server only ever reads, so SELECT is enough, except for the
-- best-effort last_used_at bump on API keys (a column-scoped UPDATE).
-- See ../rls_policy.sql for the full production hardening (explicit REVOKEs of
-- write access and dangerous built-in functions).
-- ---------------------------------------------------------------------------
GRANT CONNECT ON DATABASE pathql TO pathql_app;
GRANT USAGE ON SCHEMA public TO pathql_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pathql_app;
GRANT UPDATE (last_used_at) ON pathql_auth_api_keys TO pathql_app;

-- Defense in depth: revoke the dangerous built-in functions so a query cannot
-- sleep to cause a DoS or read/move large objects. EXECUTE on these is granted
-- to PUBLIC by default, so the revoke MUST target PUBLIC: revoking only from the
-- app role leaves the privilege it inherits through PUBLIC intact. Revoking a
-- function PUBLIC never had is a harmless no-op. This also keeps the server's
-- startup hardening self-check clean (only the intentional no-RLS tables warn).
REVOKE EXECUTE ON FUNCTION pg_read_file(text)            FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text)     FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_ls_dir(text)               FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep(double precision)    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_for(interval)        FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_import(text)               FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_export(oid, text)          FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_get(oid)                   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_get(oid, bigint, integer)  FROM PUBLIC;
