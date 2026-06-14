-- Demo data for pathql-server. Runs once, as the postgres superuser, right
-- after 01-schema.sql.

-- ---------------------------------------------------------------------------
-- Content. These exact rows reproduce the responses documented in
-- ../../README.md (e.g. post 1 is "blog started"; both posts are in
-- "announcement"; "article" has no posts; there are 2 posts and 4 comments).
-- ---------------------------------------------------------------------------
INSERT INTO categories (id, name) VALUES
  (1, 'announcement'),
  (2, 'article');

INSERT INTO posts (id, content, category_id) VALUES
  (1, 'blog started', 1),
  (2, 'second post',  1);

INSERT INTO comments (id, post_id, message) VALUES
  (1, 1, 'great!'),
  (2, 1, 'nice!'),
  (3, 2, 'interesting'),
  (4, 2, 'cool');

-- ---------------------------------------------------------------------------
-- Principals. The Basic password is bcrypt-hashed with pgcrypto; the demo
-- password is alice-password. app_user is the recorded identity (it has no
-- effect on queries in this no-RLS mode, but it is what /metrics attributes to).
--
-- "metrics" is a dedicated read-only-metrics principal: it has app_user
-- 'metrics' (the configured metrics_user), so the server lets it read GET
-- /metrics and refuses it on POST /pathql. It logs in by API key only.
-- ---------------------------------------------------------------------------
INSERT INTO pathql_auth_users (username, password_hash, app_user) VALUES
  ('alice',   crypt('alice-password', gen_salt('bf', 10)), 'alice'),
  ('metrics', NULL,                                         'metrics');

-- API keys. The server stores only sha-256(key) and the first 8 characters as
-- the (unique) lookup prefix, so the demo keys must not share a prefix.
--   alice:   pql_demo_alice_8c1f2a9b4d6e7035   (prefix pql_demo)
--   metrics: pql_metrics_3f9a1c7d5e2b8460      (prefix pql_metr)
INSERT INTO pathql_auth_api_keys (user_id, key_prefix, key_hash, name)
SELECT u.id,
       left('pql_demo_alice_8c1f2a9b4d6e7035', 8),
       digest('pql_demo_alice_8c1f2a9b4d6e7035', 'sha256'),
       'demo api key'
FROM pathql_auth_users u
WHERE u.username = 'alice';

INSERT INTO pathql_auth_api_keys (user_id, key_prefix, key_hash, name)
SELECT u.id,
       left('pql_metrics_3f9a1c7d5e2b8460', 8),
       digest('pql_metrics_3f9a1c7d5e2b8460', 'sha256'),
       'demo metrics key'
FROM pathql_auth_users u
WHERE u.username = 'metrics';
