-- Static, deploy-time setup for the login_role demo. Run once on first boot by
-- the postgres superuser (see docker-compose.yml). The server never runs any of
-- this; an operator does. The per-user login roles are added later, out of band,
-- from the DDL the server emits at /admin/roles/sync.

-- pgcrypto gives us digest() to store the API key hash in 02-seed.sql.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The baseline role the server connects as for auth lookups, admin CRUD, and
-- catalog reads (it produces the role-sync diff by reading pg_roles). It is the
-- `baseline_role` in config.ini. It is deliberately unprivileged on the data
-- tables: it can read and write the auth tables, but cannot read `documents`.
-- The password is HMAC-SHA256(password_secret, 'pathql_auth') truncated to 32
-- hex chars, with password_secret = "login-role-demo-secret" from config.ini, so
-- it matches what the server re-derives at connect time. The per-user roles get
-- their passwords the same way from the /admin/roles/sync DDL.
CREATE ROLE pathql_auth LOGIN PASSWORD 'd1033b5134f5c47bcb652023902a941f';

-- The shared reader group. Every managed per-user login role is granted
-- membership in this role; the RLS policy below grants SELECT to this group.
-- This is the `reader_role` in config.ini. It has no LOGIN of its own.
CREATE ROLE pathql_readers;

-- ---------------------------------------------------------------------------
-- Auth tables (prefix pathql_auth_, matching auth_table_prefix in config.ini)
-- ---------------------------------------------------------------------------
-- Users. app_user is the application principal; for login_role the per-user
-- database role name is derived from the id (prefix + id), e.g. user id 2 maps
-- to role pathql_r_2. The pool_* columns are per-user connection-pool overrides
-- (NULL means inherit the global default in pathql_auth_pool_settings).
CREATE TABLE pathql_auth_users (
  id bigserial PRIMARY KEY, username text UNIQUE NOT NULL, password_hash text,
  app_user text NOT NULL, enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(),
  pool_max_open int, pool_max_idle int, pool_conn_max_lifetime_ms bigint, pool_conn_max_idle_time_ms bigint);

-- API keys. The server stores only a prefix (for lookup) and a sha-256 hash of
-- the full key, never the key itself.
CREATE TABLE pathql_auth_api_keys (
  id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES pathql_auth_users(id),
  key_prefix text NOT NULL, key_hash bytea NOT NULL, name text, expires_at timestamptz,
  enabled boolean NOT NULL DEFAULT true, last_used_at timestamptz, UNIQUE(key_prefix));

-- Global connection-pool defaults, a single row keyed on id = 1. Runtime-tunable
-- via PUT /admin/pool.
CREATE TABLE pathql_auth_pool_settings (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  max_open int NOT NULL, max_idle int NOT NULL, conn_max_lifetime_ms bigint NOT NULL, conn_max_idle_time_ms bigint NOT NULL);

-- ---------------------------------------------------------------------------
-- Protected data
-- ---------------------------------------------------------------------------
-- documents.owner holds the managed role name (e.g. pathql_r_2), because the RLS
-- policy compares owner = current_user, and current_user is the per-user login
-- role the server connected as.
CREATE TABLE documents (owner text NOT NULL, body text NOT NULL);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
-- FORCE RLS so the policy applies even to the table owner. Without FORCE, a
-- superuser or the table owner would bypass RLS entirely; FORCE makes the policy
-- the only path in, which is the whole point here.
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
-- The policy: a reader may SELECT only the rows whose owner equals its own
-- connected role name. current_user cannot be forged from query text, so this is
-- the unforgeable identity boundary.
CREATE POLICY documents_self ON documents FOR SELECT TO pathql_readers USING (owner = current_user);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
-- Both roles may connect and see the public schema.
GRANT CONNECT ON DATABASE pathql TO pathql_auth, pathql_readers;
GRANT USAGE ON SCHEMA public TO pathql_auth, pathql_readers;
-- The baseline role manages the auth tables (lookups during login, admin CRUD,
-- the best-effort last_used_at touch, per-user pool overrides) and the global
-- pool settings row.
GRANT SELECT, INSERT, UPDATE, DELETE ON pathql_auth_users, pathql_auth_api_keys TO pathql_auth;
GRANT SELECT, INSERT, UPDATE ON pathql_auth_pool_settings TO pathql_auth;
-- INSERT into the bigserial-keyed tables needs the sequences too.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pathql_auth;
-- Readers may SELECT documents; the RLS policy above then filters to own rows.
GRANT SELECT ON documents TO pathql_readers;

-- Defense in depth: revoke the dangerous built-in functions from PUBLIC so no
-- role (managed or baseline) can sleep to cause a DoS or move large objects.
-- Revoking from PUBLIC is what actually removes the privilege; a role-targeted
-- revoke would leave the PUBLIC grant intact. Also keeps the startup check clean.
REVOKE EXECUTE ON FUNCTION pg_sleep(double precision)   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_for(interval)       FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_get(oid)                  FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_get(oid, bigint, integer) FROM PUBLIC;
