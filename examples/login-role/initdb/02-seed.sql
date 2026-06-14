-- Bootstrap admin principal (app_user 'admin'); its API key is adminkey_0001.
-- The admin principal is allowed only on /admin/*; it cannot run /pathql.
INSERT INTO pathql_auth_users (username, app_user) VALUES ('admin','admin');
INSERT INTO pathql_auth_api_keys (user_id, key_prefix, key_hash, name)
  SELECT id, 'adminkey', digest('adminkey_0001','sha256'), 'bootstrap' FROM pathql_auth_users WHERE username='admin';

-- Seed the global pool defaults (single row, id = 1).
INSERT INTO pathql_auth_pool_settings (id, max_open, max_idle, conn_max_lifetime_ms, conn_max_idle_time_ms)
  VALUES (1, 50, 10, 300000, 60000);

-- Documents owned by the roles the first two added users will map to. owner
-- holds the managed role NAME, not a username, because RLS compares
-- owner = current_user and current_user is the connected per-user login role.
-- (user id 2 -> pathql_r_2 = alice, id 3 -> pathql_r_3 = bob.)
INSERT INTO documents (owner, body) VALUES
  ('pathql_r_2','alice-secret-1'), ('pathql_r_2','alice-secret-2'), ('pathql_r_3','bob-secret');
