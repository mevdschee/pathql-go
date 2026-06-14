-- pathql-server authentication schema (PostgreSQL).
--
-- These are the two tables the internal/auth UserStore reads, shown with the
-- default table prefix "pathql_auth_". If you change AuthTablePrefix in the
-- config, rename these tables to use the same prefix (e.g. "myauth_users",
-- "myauth_api_keys"). The prefix must match ^[A-Za-z_][A-Za-z0-9_]*$.
--
-- Secrets are never stored in clear text:
--   * passwords  -> bcrypt hash in users.password_hash (NULL/'' disables Basic)
--   * API keys   -> sha-256(full key) in api_keys.key_hash (bytea), looked up by
--                   the non-secret api_keys.key_prefix (first 8 chars of the key)

-- principals
CREATE TABLE pathql_auth_users (
  id            bigserial PRIMARY KEY,
  username      text NOT NULL UNIQUE,
  password_hash text,                      -- bcrypt; NULL/'' disables HTTP Basic
  app_user      text NOT NULL,             -- value pushed into the RLS session variable
  enabled       boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- API keys (store only a hash, never the raw key)
CREATE TABLE pathql_auth_api_keys (
  id           bigserial PRIMARY KEY,
  user_id      bigint NOT NULL REFERENCES pathql_auth_users(id),
  key_prefix   text NOT NULL,              -- first 8 chars of the key, for lookup + display
  key_hash     bytea NOT NULL,             -- sha-256 of the full key
  name         text,
  expires_at   timestamptz,                -- NULL = never expires
  enabled      boolean NOT NULL DEFAULT true,
  last_used_at timestamptz,
  UNIQUE (key_prefix)
);

-- ---------------------------------------------------------------------------
-- Inserting a user (HTTP Basic)
-- ---------------------------------------------------------------------------
-- Generate a bcrypt hash of the password outside the database, e.g. with the
-- Go helper bcrypt.GenerateFromPassword, the `htpasswd -nbB user pass` tool, or
-- Python's passlib. Then:
--
--   INSERT INTO pathql_auth_users (username, password_hash, app_user)
--   VALUES ('alice', '$2a$10$....bcrypt-hash....', 'alice');
--
-- The app_user column is what RLS will see; default it to the username, or set
-- it to a tenant id / database role as needed. Leave password_hash NULL to
-- disable Basic login for that user (e.g. an API-key-only account).

-- ---------------------------------------------------------------------------
-- Inserting an API key
-- ---------------------------------------------------------------------------
-- 1. Generate a random key client-side, e.g. 32 random bytes hex/base64 encoded.
--    Show the FULL key to the operator exactly once; the server only stores its
--    hash and prefix.
-- 2. key_prefix = the first 8 characters of the key (non-secret, for lookup).
-- 3. key_hash   = sha-256(full key) as bytea.
--
-- If you have the full key as a literal you can compute both in SQL:
--
--   INSERT INTO pathql_auth_api_keys (user_id, key_prefix, key_hash, name)
--   SELECT u.id,
--          left('THEFULLKEYVALUE', 8),
--          digest('THEFULLKEYVALUE', 'sha256'),   -- requires pgcrypto
--          'my application key'
--   FROM pathql_auth_users u
--   WHERE u.username = 'alice';
--
-- (CREATE EXTENSION IF NOT EXISTS pgcrypto; provides digest().) Alternatively
-- compute sha-256 in the application and pass the 32-byte digest as a bound
-- bytea parameter. Set expires_at to limit the key's lifetime; NULL never
-- expires.

-- ---------------------------------------------------------------------------
-- login_role pool tuning (only needed when security.identity_kind = "login_role")
-- ---------------------------------------------------------------------------
-- Per-user connection-pool overrides, set via PUT /admin/users/{id}/pool. NULL
-- means inherit the global default.
ALTER TABLE pathql_auth_users
  ADD COLUMN IF NOT EXISTS pool_max_open              int,
  ADD COLUMN IF NOT EXISTS pool_max_idle              int,
  ADD COLUMN IF NOT EXISTS pool_conn_max_lifetime_ms  bigint,
  ADD COLUMN IF NOT EXISTS pool_conn_max_idle_time_ms bigint;

-- Global pool defaults, runtime-tunable via PUT /admin/pool. A single row keyed
-- on id = 1; seeded from config.ini on first start if absent.
CREATE TABLE IF NOT EXISTS pathql_auth_pool_settings (
  id                    smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  max_open              int    NOT NULL,
  max_idle              int    NOT NULL,
  conn_max_lifetime_ms  bigint NOT NULL,
  conn_max_idle_time_ms bigint NOT NULL
);
