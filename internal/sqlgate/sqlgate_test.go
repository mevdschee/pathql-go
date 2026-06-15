package sqlgate

import "testing"

func TestValidMode(t *testing.T) {
	for _, m := range []string{"off", "on"} {
		if !ValidMode(m) {
			t.Errorf("ValidMode(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"", "ON", "strict", "yes", "true"} {
		if ValidMode(m) {
			t.Errorf("ValidMode(%q) = true, want false", m)
		}
	}
}

func TestCheckOffAllowsEverything(t *testing.T) {
	// Off must never reject, even blatantly dangerous input.
	for _, q := range []string{
		"SELECT 1; DROP TABLE users",
		"SELECT * FROM pg_catalog.pg_authid",
		"DELETE FROM users",
		"",
	} {
		if err := Check(q, ModeOff); err != nil {
			t.Errorf("Check(%q, off) = %v, want nil", q, err)
		}
	}
}

func TestCheckAllowed(t *testing.T) {
	allowed := []struct {
		name, query string
	}{
		{"simple select", "SELECT id, content FROM posts WHERE id = :id"},
		{"lower case", "select 1"},
		{"trailing semicolon", "SELECT 1;"},
		{"trailing semicolon and comment", "SELECT 1; -- done"},
		{"join", "SELECT p.id, c.id FROM posts p LEFT JOIN comments c ON c.post_id = p.id"},
		{"cte", "WITH recent AS (SELECT id FROM posts ORDER BY id DESC) SELECT * FROM recent"},
		{"subquery", "SELECT (SELECT count(*) FROM posts) AS posts"},
		{"leading paren / set op", "(SELECT id FROM a) UNION (SELECT id FROM b)"},
		{"table statement", "TABLE posts"},
		{"values statement", "VALUES (1), (2)"},
		{"non-catalog name starting with pg in middle", "SELECT pageviews FROM pages"},
		{"column literally named status", "SELECT status FROM jobs"},
		// content that only looks dangerous because it is inside a literal:
		{"semicolon in string", "SELECT ';' AS sep FROM posts"},
		{"catalog name in string", "SELECT 'pg_class' AS t, 'information_schema' AS s"},
		{"keywords in string", "SELECT 'DROP TABLE users; --' AS x"},
		{"semicolon in line comment", "SELECT 1 -- ; DROP TABLE users\n FROM posts"},
		{"catalog in block comment", "SELECT /* pg_authid ; */ 1 FROM posts"},
		{"nested block comment", "SELECT /* a /* b ; pg_class */ c */ 1"},
		{"dollar quoted body", "SELECT $$ ; DROP pg_class $$ AS x"},
		{"tagged dollar quote", "SELECT $tag$ ; pg_authid $tag$ AS x"},
		{"escape string with escaped quote then semicolon", `SELECT E'a\'; DROP TABLE t' AS x`},
		{"doubled quote in string", "SELECT 'O''Brien; drop' AS name"},
		{"quoted identifier with reserved word", `SELECT "select", "from" FROM t`},
		{"positional param", "SELECT * FROM posts WHERE id = $1"},
	}
	for _, tc := range allowed {
		if err := Check(tc.query, ModeOn); err != nil {
			t.Errorf("%s: Check(%q) = %v, want nil", tc.name, tc.query, err)
		}
	}
}

func TestCheckRejected(t *testing.T) {
	rejected := []struct {
		name, query string
		want        error
	}{
		{"empty", "", errEmpty},
		{"whitespace only", "   \n\t ", errEmpty},
		{"comment only", "-- just a comment", errEmpty},
		{"stacked statements", "SELECT 1; SELECT 2", errMultiple},
		{"stacked with drop", "SELECT 1; DROP TABLE users", errMultiple},
		{"empty second statement", "SELECT 1;;", errMultiple},
		{"semicolon mid query", "SELECT 1; -- x\n SELECT 2", errMultiple},
		{"insert", "INSERT INTO users (name) VALUES ('x')", errNotRead},
		{"update", "UPDATE users SET name = 'x'", errNotRead},
		{"delete", "DELETE FROM users", errNotRead},
		{"set", "SET work_mem = '1GB'", errNotRead},
		{"show", "SHOW all", errNotRead},
		{"explain", "EXPLAIN SELECT 1", errNotRead},
		{"explain analyze", "EXPLAIN ANALYZE SELECT * FROM posts", errNotRead},
		{"copy", "COPY posts TO STDOUT", errNotRead},
		{"call", "CALL do_something()", errNotRead},
		{"do block", "DO $$ BEGIN END $$", errNotRead},
		{"create", "CREATE TABLE x (id int)", errNotRead},
		{"drop", "DROP TABLE users", errNotRead},
		{"grant", "GRANT SELECT ON posts TO bob", errNotRead},
		{"catalog schema qualified", "SELECT * FROM pg_catalog.pg_class", errCatalog},
		{"catalog bare table", "SELECT relname FROM pg_class", errCatalog},
		{"catalog function", "SELECT pg_sleep(10)", errCatalog},
		{"catalog stat view", "SELECT * FROM pg_stat_activity", errCatalog},
		{"information_schema", "SELECT table_name FROM information_schema.tables", errCatalog},
		{"quoted catalog identifier", `SELECT * FROM "pg_class"`, errCatalog},
		{"catalog in cte", "WITH x AS (SELECT * FROM pg_authid) SELECT * FROM x", errCatalog},
	}
	for _, tc := range rejected {
		err := Check(tc.query, ModeOn)
		if err == nil {
			t.Errorf("%s: Check(%q) = nil, want %v", tc.name, tc.query, tc.want)
			continue
		}
		if err != tc.want {
			t.Errorf("%s: Check(%q) = %v, want %v", tc.name, tc.query, err, tc.want)
		}
	}
}

// TestCheckUnknownModeFailsClosed verifies an unrecognised mode is treated as
// strict (the on checks) rather than silently allowing everything.
func TestCheckUnknownModeFailsClosed(t *testing.T) {
	if err := Check("SELECT * FROM pg_class", Mode("future-mode")); err == nil {
		t.Error("Check with unknown mode allowed a catalog query; want fail-closed rejection")
	}
}

func TestClassifyReads(t *testing.T) {
	reads := []struct{ name, query string }{
		{"simple select", "SELECT id FROM posts"},
		{"lower case", "select 1"},
		{"trailing semicolon", "SELECT 1;"},
		{"table statement", "TABLE posts"},
		{"values statement", "VALUES (1), (2)"},
		{"leading paren / set op", "(SELECT id FROM a) UNION (SELECT id FROM b)"},
		{"insert keyword in string is read", "SELECT 'INSERT INTO' AS x"},
	}
	for _, tc := range reads {
		got, err := Classify(tc.query)
		if err != nil {
			t.Errorf("%s: Classify(%q) error = %v, want nil", tc.name, tc.query, err)
			continue
		}
		if got != ClassRead {
			t.Errorf("%s: Classify(%q) = %v, want ClassRead", tc.name, tc.query, got)
		}
	}
}

func TestClassifyWrites(t *testing.T) {
	writes := []struct{ name, query string }{
		{"insert", "INSERT INTO posts (content) VALUES ('x')"},
		{"insert returning", "INSERT INTO posts (content) VALUES ('x') RETURNING id"},
		{"update", "UPDATE posts SET content = 'x' WHERE id = :id"},
		{"delete", "DELETE FROM posts WHERE id = :id"},
		{"lower case insert", "insert into posts (content) values ('x')"},
		// WITH is conservatively a write (it may wrap a modifying CTE); it runs in
		// a read-write transaction where a read-only WITH is still valid.
		{"with select", "WITH recent AS (SELECT id FROM posts) SELECT * FROM recent"},
		{"with modifying cte", "WITH d AS (DELETE FROM posts WHERE id = 1 RETURNING id) SELECT * FROM d"},
	}
	for _, tc := range writes {
		got, err := Classify(tc.query)
		if err != nil {
			t.Errorf("%s: Classify(%q) error = %v, want nil", tc.name, tc.query, err)
			continue
		}
		if got != ClassWrite {
			t.Errorf("%s: Classify(%q) = %v, want ClassWrite", tc.name, tc.query, got)
		}
	}
}

func TestClassifyRejected(t *testing.T) {
	rejected := []struct {
		name, query string
		want        error
	}{
		{"empty", "", errEmpty},
		{"comment only", "-- just a comment", errEmpty},
		{"stacked statements", "INSERT INTO t VALUES (1); DROP TABLE t", errMultiple},
		{"stacked selects", "SELECT 1; SELECT 2", errMultiple},
		{"truncate", "TRUNCATE posts", errNotAllowed},
		{"create", "CREATE TABLE x (id int)", errNotAllowed},
		{"drop", "DROP TABLE posts", errNotAllowed},
		{"alter", "ALTER TABLE posts ADD COLUMN x int", errNotAllowed},
		{"grant", "GRANT SELECT ON posts TO bob", errNotAllowed},
		{"set", "SET work_mem = '1GB'", errNotAllowed},
		{"copy", "COPY posts TO STDOUT", errNotAllowed},
		{"call", "CALL do_something()", errNotAllowed},
		{"do block", "DO $$ BEGIN END $$", errNotAllowed},
		{"catalog write", "UPDATE pg_authid SET rolsuper = true", errCatalog},
		{"catalog read", "SELECT * FROM pg_class", errCatalog},
		{"information_schema", "SELECT table_name FROM information_schema.tables", errCatalog},
	}
	for _, tc := range rejected {
		_, err := Classify(tc.query)
		if err == nil {
			t.Errorf("%s: Classify(%q) = nil, want %v", tc.name, tc.query, tc.want)
			continue
		}
		if err != tc.want {
			t.Errorf("%s: Classify(%q) = %v, want %v", tc.name, tc.query, err, tc.want)
		}
	}
}

func TestHasReturning(t *testing.T) {
	with := []string{
		"INSERT INTO posts (content) VALUES ('x') RETURNING id",
		"insert into posts (content) values ('x') returning id, content",
		"DELETE FROM posts WHERE id = 1 RETURNING *",
		"UPDATE posts SET content = 'x' RETURNING id",
	}
	for _, q := range with {
		if !HasReturning(q) {
			t.Errorf("HasReturning(%q) = false, want true", q)
		}
	}
	without := []string{
		"INSERT INTO posts (content) VALUES ('x')",
		"UPDATE posts SET content = 'x' WHERE id = 1",
		"SELECT id FROM posts",
		// "returning" only inside a string literal or comment must not count.
		"INSERT INTO posts (content) VALUES ('returning soon')",
		"INSERT INTO posts (content) VALUES ('x') -- returning id",
	}
	for _, q := range without {
		if HasReturning(q) {
			t.Errorf("HasReturning(%q) = true, want false", q)
		}
	}
}
