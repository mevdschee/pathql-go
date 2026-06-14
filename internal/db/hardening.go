package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/mevdschee/pathsqlx"
)

// HardeningReport is the result of the startup database hardening self-check.
// It separates findings that undermine the core security guarantees (Critical)
// from weaker ones worth surfacing (Warnings).
type HardeningReport struct {
	// Critical findings break the boundary the whole design rests on: a
	// superuser role (bypasses RLS and read-only) or a role that can write.
	Critical []string
	// Warnings are findings to surface but not necessarily fatal: executable
	// file/sleep/large-object functions, or readable tables without RLS.
	Warnings []string
}

// Empty reports whether the check found nothing.
func (r *HardeningReport) Empty() bool { return len(r.Critical) == 0 && len(r.Warnings) == 0 }

// VerifyHardening runs read-only catalog queries to check the connected role's
// posture: it is not a superuser, has no write privileges outside the auth
// tables, cannot execute file/sleep/large-object functions, and that every
// table it can read has row-level security enabled. It is PostgreSQL-specific;
// for any other driver it returns an empty report.
//
// authTablePrefix scopes out the server's own auth tables, which it legitimately
// reads and updates (last_used_at), so the column-level write grant they need
// does not register as a finding.
func VerifyHardening(ctx context.Context, pool *pathsqlx.DB, driver, authTablePrefix string) (*HardeningReport, error) {
	rep := &HardeningReport{}
	if driver != "postgres" {
		return rep, nil
	}
	db := pool.DB
	like := authTablePrefix + "%"

	var isSuper bool
	if err := db.QueryRowContext(ctx, `SELECT current_setting('is_superuser')::boolean`).Scan(&isSuper); err != nil {
		return nil, fmt.Errorf("hardening: superuser check: %w", err)
	}
	if isSuper {
		rep.Critical = append(rep.Critical,
			"connected database role is a SUPERUSER: it bypasses row-level security and read-only transactions - connect as a least-privilege login role instead")
	}

	writable, err := scanStrings(ctx, db, `
SELECT n.nspname || '.' || c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname !~ '^pg_'
  AND c.relname NOT LIKE $1
  AND (has_table_privilege(c.oid,'INSERT') OR has_table_privilege(c.oid,'UPDATE') OR has_table_privilege(c.oid,'DELETE'))
ORDER BY 1
LIMIT 25`, like)
	if err != nil {
		return nil, fmt.Errorf("hardening: write-privilege check: %w", err)
	}
	if len(writable) > 0 {
		rep.Critical = append(rep.Critical,
			fmt.Sprintf("connected role can write (INSERT/UPDATE/DELETE) to %d table(s): %s - grant it only SELECT",
				len(writable), strings.Join(writable, ", ")))
	}

	dangerous, err := scanStrings(ctx, db, `
SELECT p.oid::regprocedure::text
FROM pg_proc p
WHERE p.proname IN ('pg_read_file','pg_read_binary_file','pg_ls_dir','pg_sleep','pg_sleep_for','lo_import','lo_export','lo_get','dblink','dblink_exec')
  AND has_function_privilege(p.oid,'execute')
ORDER BY 1
LIMIT 25`)
	if err != nil {
		return nil, fmt.Errorf("hardening: dangerous-function check: %w", err)
	}
	if len(dangerous) > 0 {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("connected role may EXECUTE %d sensitive function(s): %s - REVOKE EXECUTE from the role (see examples/rls_policy.sql)",
				len(dangerous), strings.Join(dangerous, ", ")))
	}

	noRLS, err := scanStrings(ctx, db, `
SELECT n.nspname || '.' || c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname !~ '^pg_'
  AND c.relname NOT LIKE $1
  AND has_table_privilege(c.oid,'SELECT')
  AND NOT c.relrowsecurity
ORDER BY 1
LIMIT 50`, like)
	if err != nil {
		return nil, fmt.Errorf("hardening: rls-coverage check: %w", err)
	}
	if len(noRLS) > 0 {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("%d readable table(s) have NO row-level security, so every authenticated caller can read all of their rows: %s",
				len(noRLS), strings.Join(noRLS, ", ")))
	}

	return rep, nil
}

// scanStrings runs query and collects the first column of every row as a string.
func scanStrings(ctx context.Context, db *sqlx.DB, query string, args ...interface{}) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
