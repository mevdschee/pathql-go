-- Example row-level-security setup for pathql-server.
--
-- pathql-server runs every query inside a read-only transaction and binds the
-- authenticated identity to a Postgres session variable (default "app.user")
-- with set_config('app.user', <identity>, true). Your policies read that value
-- with current_setting('app.user', true). The second argument (true) makes the
-- lookup return NULL instead of raising when the variable is unset, so a request
-- without an authenticated identity simply matches no rows.
--
-- This script is meant to be read and adapted, not run blindly. It assumes a
-- table `documents` with an `owner` column that holds the app_user value. Run it
-- as a privileged role (the owner of the tables); the application connects as a
-- separate, least-privilege role created below.

-- ---------------------------------------------------------------------------
-- 1. A least-privilege application role.
-- ---------------------------------------------------------------------------
-- The application must NOT be a superuser and must NOT own the tables, because
-- table owners and superusers bypass row-level security. Create a dedicated
-- login role with only the privileges it needs.

-- CREATE ROLE pathql_app LOGIN PASSWORD 'set-via-secret-manager';

-- Let it connect and see the schema, nothing more by default.
GRANT CONNECT ON DATABASE pathql TO pathql_app;
GRANT USAGE ON SCHEMA public TO pathql_app;

-- SELECT-only: pathql-server opens read-only transactions, so the role never
-- needs write access. Granting only SELECT is defense in depth in case the
-- read-only setting is ever misconfigured.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pathql_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pathql_app;

-- Explicitly deny write and structural access. (These are not granted above,
-- but REVOKE makes the intent explicit and undoes any broad prior grant.)
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON ALL TABLES IN SCHEMA public FROM pathql_app;
REVOKE CREATE ON SCHEMA public FROM pathql_app;

-- ---------------------------------------------------------------------------
-- 2. Remove dangerous built-in functions.
-- ---------------------------------------------------------------------------
-- EXECUTE on these is granted to PUBLIC by default, so the revoke MUST target
-- PUBLIC: revoking only from pathql_app leaves the privilege it still inherits
-- through PUBLIC (has_function_privilege would keep reporting true). Revoking a
-- function PUBLIC never had is a harmless no-op. This stops a query from sleeping
-- to cause a DoS or reading/moving large objects. (pg_read_file and friends are
-- already superuser-only by default; revoking them is belt-and-braces.)

REVOKE EXECUTE ON FUNCTION pg_read_file(text)            FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text)     FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_ls_dir(text)               FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep(double precision)    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_for(interval)        FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_import(text)               FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_export(oid, text)          FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_get(oid)                   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION lo_get(oid, bigint, integer)  FROM PUBLIC;

-- If the dblink or postgres_fdw extensions are installed they are an SSRF /
-- exfiltration vector; revoke their functions from PUBLIC too (no-op when the
-- extension is absent), or better, do not install them on a database backing
-- pathql-server.
-- REVOKE EXECUTE ON FUNCTION dblink(text, text)      FROM PUBLIC;
-- REVOKE EXECUTE ON FUNCTION dblink_exec(text, text) FROM PUBLIC;

-- COPY ... TO/FROM a file requires superuser or the pg_read_server_files /
-- pg_write_server_files roles. Do not grant those roles to pathql_app, and the
-- read-only transaction blocks COPY ... FROM regardless. COPY ... TO STDOUT is
-- harmless and need not be blocked.

-- ---------------------------------------------------------------------------
-- 3. Enable row-level security and define the policy.
-- ---------------------------------------------------------------------------

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
-- FORCE so the table owner is subject to the policy too (useful when testing as
-- the owner; the application role is already non-owner).
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- One read policy: a row is visible only when its owner matches the identity
-- bound by pathql-server. current_setting('app.user', true) is NULL when no
-- identity was set, so unauthenticated access matches no rows.
DROP POLICY IF EXISTS documents_owner_select ON documents;
CREATE POLICY documents_owner_select
  ON documents
  FOR SELECT
  TO pathql_app
  USING (owner = current_setting('app.user', true));

-- ---------------------------------------------------------------------------
-- 4. Quick manual check (run as a privileged role).
-- ---------------------------------------------------------------------------
-- BEGIN READ ONLY;
--   SELECT set_config('app.user', 'alice', true);
--   SELECT * FROM documents;   -- only alice's rows
-- ROLLBACK;
