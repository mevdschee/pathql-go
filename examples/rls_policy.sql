-- Example row-level-security setup for pathql-server.
--
-- pathql-server runs every query inside a read-only transaction on a connection
-- authenticated as the caller's own database role (the per-user "login role").
-- Your policies read that identity with current_user, which a caller cannot
-- forge from query text. There is no session variable: the connected role IS the
-- identity boundary.
--
-- A user with id N maps to the login role <prefix>N (default prefix "pathql_r_").
-- The server never creates roles itself; it emits the CREATE/GRANT/DROP DDL at
-- GET /admin/roles/sync for an operator (or cron) to apply out of band. This
-- script shows the static, deploy-time pieces; adapt it, do not run it blindly.
-- It assumes a table `documents` with an `owner` column that holds the login
-- role name (e.g. "pathql_r_2"). Run it as a privileged role that owns the
-- tables; the application connects as the per-user roles created below.

-- ---------------------------------------------------------------------------
-- 1. The baseline and reader roles.
-- ---------------------------------------------------------------------------
-- The baseline role is what the server connects as before the caller is known,
-- to read the auth tables and the catalog. It is the `baseline_role` in
-- config.ini and is deliberately unprivileged on the data tables.
-- CREATE ROLE pathql_auth LOGIN PASSWORD 'set-via-secret-manager';

-- The reader group grants read access to the data tables. Every per-user login
-- role is granted membership in it; the RLS policy below targets it. It is the
-- `reader_role` in config.ini and has no LOGIN of its own.
-- CREATE ROLE pathql_readers;

-- Let the readers connect and see the schema, nothing more by default.
GRANT CONNECT ON DATABASE pathql TO pathql_readers;
GRANT USAGE ON SCHEMA public TO pathql_readers;

-- SELECT-only: pathql-server opens read-only transactions, so the role never
-- needs write access. Granting only SELECT is defense in depth in case the
-- read-only setting is ever misconfigured.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pathql_readers;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO pathql_readers;

-- Explicitly deny write and structural access. (These are not granted above,
-- but REVOKE makes the intent explicit and undoes any broad prior grant.)
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON ALL TABLES IN SCHEMA public FROM pathql_readers;
REVOKE CREATE ON SCHEMA public FROM pathql_readers;

-- The per-user login roles are added later, out of band, from the sync DDL the
-- server emits. Each is a member of pathql_readers and connects with a password
-- derived as HMAC-SHA256(roles.password_secret, role). For example user id 2:
-- CREATE ROLE pathql_r_2 LOGIN PASSWORD '<derived>';
-- GRANT pathql_readers TO pathql_r_2;

-- ---------------------------------------------------------------------------
-- 2. Remove dangerous built-in functions.
-- ---------------------------------------------------------------------------
-- EXECUTE on these is granted to PUBLIC by default, so the revoke MUST target
-- PUBLIC: revoking only from a managed role leaves the privilege it still
-- inherits through PUBLIC (has_function_privilege would keep reporting true).
-- Revoking a function PUBLIC never had is a harmless no-op. This stops a query
-- from sleeping to cause a DoS or reading/moving large objects. (pg_read_file
-- and friends are already superuser-only by default; revoking them is
-- belt-and-braces.)

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
-- pg_write_server_files roles. Do not grant those roles to the managed roles,
-- and the read-only transaction blocks COPY ... FROM regardless. COPY ... TO
-- STDOUT is harmless and need not be blocked.

-- ---------------------------------------------------------------------------
-- 3. Enable row-level security and define the policy.
-- ---------------------------------------------------------------------------

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
-- FORCE so the table owner is subject to the policy too (useful when testing as
-- the owner; the per-user roles are already non-owner).
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- One read policy: a row is visible only when its owner matches the connected
-- role name. current_user is the per-user login role pathql-server connected as,
-- and it cannot be forged from query text, so this is the identity boundary.
DROP POLICY IF EXISTS documents_owner_select ON documents;
CREATE POLICY documents_owner_select
  ON documents
  FOR SELECT
  TO pathql_readers
  USING (owner = current_user);

-- ---------------------------------------------------------------------------
-- 4. Quick manual check (run as a privileged role).
-- ---------------------------------------------------------------------------
-- BEGIN READ ONLY;
--   SET LOCAL ROLE pathql_r_2;   -- impersonate a managed login role
--   SELECT * FROM documents;     -- only that role's rows
-- ROLLBACK;

-- ---------------------------------------------------------------------------
-- 5. OPTIONAL: writes (only when security.writes = "on").
-- ---------------------------------------------------------------------------
-- Everything above is read-only and is all most deployments need. The block
-- below is OFF by default; apply it only if you set security.writes = "on" and
-- want the per-user roles to INSERT/UPDATE/DELETE through pathql-server.
--
-- The critical part is the WITH CHECK clause. A SELECT policy's USING clause
-- filters which rows a caller can SEE; it does NOT constrain which rows a caller
-- can CREATE or CHANGE. Without WITH CHECK, a caller could insert a row owned by
-- another role, or update a row to hand it to another role - a cross-tenant write
-- hole. WITH CHECK applies the same owner = current_user test to the NEW row, so
-- a caller can only write rows that remain its own.
--
-- Grant the writes (in addition to the SELECT granted in section 1):
-- GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pathql_readers;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA public
--   GRANT INSERT, UPDATE, DELETE ON TABLES TO pathql_readers;
--
-- Then add per-command policies with WITH CHECK on the new row:
-- DROP POLICY IF EXISTS documents_owner_insert ON documents;
-- CREATE POLICY documents_owner_insert
--   ON documents
--   FOR INSERT
--   TO pathql_readers
--   WITH CHECK (owner = current_user);
--
-- DROP POLICY IF EXISTS documents_owner_update ON documents;
-- CREATE POLICY documents_owner_update
--   ON documents
--   FOR UPDATE
--   TO pathql_readers
--   USING (owner = current_user)        -- the rows the caller may target
--   WITH CHECK (owner = current_user);  -- the rows it may leave behind
--
-- DROP POLICY IF EXISTS documents_owner_delete ON documents;
-- CREATE POLICY documents_owner_delete
--   ON documents
--   FOR DELETE
--   TO pathql_readers
--   USING (owner = current_user);
--
-- A common pattern is to default the owner column to the connected role so a
-- client never has to send it:
-- ALTER TABLE documents ALTER COLUMN owner SET DEFAULT current_user;
--
-- With security.startup_checks = "enforce" under login_role, the server refuses
-- to start if a writable table has no WITH CHECK policy, so a missing policy here
-- is caught at boot rather than becoming a silent cross-tenant write.
