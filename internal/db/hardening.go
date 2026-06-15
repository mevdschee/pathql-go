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
	// superuser or BYPASSRLS role (bypasses RLS and read-only), a role that can
	// write, or - when RLS is the enforced boundary - a readable table with no
	// row-level security.
	Critical []string
	// Warnings are findings to surface but not necessarily fatal: executable
	// file/sleep/large-object functions, readable tables without RLS (outside
	// enforce mode), owner-bypassable (non-forced) RLS, or RLS enabled with no
	// policy.
	Warnings []string
}

// Empty reports whether the check found nothing.
func (r *HardeningReport) Empty() bool { return len(r.Critical) == 0 && len(r.Warnings) == 0 }

// VerifyHardening runs read-only catalog queries to check the connected role's
// posture: it is not a superuser, does not hold the BYPASSRLS attribute, has no
// write privileges outside the auth tables, cannot execute
// file/sleep/large-object functions, and that every table it can read has
// row-level security enabled and forced. It is PostgreSQL-specific; for any
// other driver it returns an empty report.
//
// authTablePrefix scopes out the server's own auth tables, which it legitimately
// reads and updates (last_used_at), so the column-level write grant they need
// does not register as a finding.
//
// noRLSIsCritical decides where a readable table with no row-level security is
// reported: as a Critical finding (when RLS is the security boundary and the
// operator asked to enforce it) or a Warning. The caller sets it when
// identity_kind is login_role and startup_checks is enforce, so a silent
// full-table exposure aborts startup only where RLS is actually relied upon.
//
// writesEnabled changes how a write privilege is judged. When writes are off the
// server promises read-only, so any write grant is Critical. When writes are on
// a write grant is expected and is not itself a finding; instead, where RLS is
// the enforced boundary (writeRLSIsCritical), a writable table that lacks a
// WITH CHECK policy is Critical, since RLS without WITH CHECK filters which rows
// a write can see but not which it can create or change - a silent cross-tenant
// write path.
func VerifyHardening(ctx context.Context, pool *pathsqlx.DB, driver, authTablePrefix string, noRLSIsCritical, writesEnabled, writeRLSIsCritical bool) (*HardeningReport, error) {
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

	var bypassRLS bool
	if err := db.QueryRowContext(ctx, `SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypassRLS); err != nil {
		return nil, fmt.Errorf("hardening: bypassrls check: %w", err)
	}
	if bypassRLS {
		rep.Critical = append(rep.Critical,
			"connected database role has the BYPASSRLS attribute: it bypasses every row-level-security policy - run ALTER ROLE ... NOBYPASSRLS")
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
	if len(writable) > 0 && !writesEnabled {
		// Writes are off, so the server promises read-only: any write grant
		// contradicts that and is critical.
		rep.Critical = append(rep.Critical,
			fmt.Sprintf("connected role can write (INSERT/UPDATE/DELETE) to %d table(s): %s - grant it only SELECT",
				len(writable), strings.Join(writable, ", ")))
	}

	// With writes enabled and RLS the enforced boundary, a writable table needs a
	// WITH CHECK policy or a caller could create/update rows attributed to another
	// tenant. Report writable tables that have no WITH CHECK policy at all. The
	// caller escalates to critical only under login_role + enforce
	// (writeRLSIsCritical); otherwise it is a warning.
	if len(writable) > 0 && writesEnabled {
		noWithCheck, err := scanStrings(ctx, db, `
SELECT n.nspname || '.' || c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname !~ '^pg_'
  AND c.relname NOT LIKE $1
  AND (has_table_privilege(c.oid,'INSERT') OR has_table_privilege(c.oid,'UPDATE'))
  AND NOT EXISTS (
    SELECT 1 FROM pg_policy p
    WHERE p.polrelid = c.oid AND p.polwithcheck IS NOT NULL
  )
ORDER BY 1
LIMIT 50`, like)
		if err != nil {
			return nil, fmt.Errorf("hardening: with-check coverage check: %w", err)
		}
		if len(noWithCheck) > 0 {
			finding := fmt.Sprintf("%d writable table(s) have NO row-level-security WITH CHECK policy, so a caller could insert or update rows attributed to another identity: %s - add FOR INSERT/UPDATE policies WITH CHECK",
				len(noWithCheck), strings.Join(noWithCheck, ", "))
			if writeRLSIsCritical {
				rep.Critical = append(rep.Critical, finding)
			} else {
				rep.Warnings = append(rep.Warnings, finding)
			}
		}
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
		finding := fmt.Sprintf("%d readable table(s) have NO row-level security, so every authenticated caller can read all of their rows: %s",
			len(noRLS), strings.Join(noRLS, ", "))
		if noRLSIsCritical {
			rep.Critical = append(rep.Critical, finding)
		} else {
			rep.Warnings = append(rep.Warnings, finding)
		}
	}

	// Tables the connected role OWNS whose RLS is enabled but not FORCED: a table
	// owner bypasses its own (non-forced) policies, so the role would read every
	// row despite the policy. A least-privilege query role should own nothing;
	// where it does, RLS must be forced to apply to it.
	ownedUnforced, err := scanStrings(ctx, db, `
SELECT n.nspname || '.' || c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname !~ '^pg_'
  AND c.relname NOT LIKE $1
  AND pg_get_userbyid(c.relowner) = current_user
  AND c.relrowsecurity AND NOT c.relforcerowsecurity
ORDER BY 1
LIMIT 25`, like)
	if err != nil {
		return nil, fmt.Errorf("hardening: force-rls check: %w", err)
	}
	if len(ownedUnforced) > 0 {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("connected role OWNS %d table(s) with row-level security enabled but NOT forced, so as the owner it bypasses their policies: %s - run ALTER TABLE ... FORCE ROW LEVEL SECURITY",
				len(ownedUnforced), strings.Join(ownedUnforced, ", ")))
	}

	// Tables with RLS enabled but no policy at all: PostgreSQL applies a
	// default-deny, so these return no rows. That is safe, but is reported so an
	// operator can tell an intentional lockdown from a forgotten policy.
	noPolicy, err := scanStrings(ctx, db, `
SELECT n.nspname || '.' || c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname !~ '^pg_'
  AND c.relname NOT LIKE $1
  AND has_table_privilege(c.oid,'SELECT')
  AND c.relrowsecurity
  AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
ORDER BY 1
LIMIT 50`, like)
	if err != nil {
		return nil, fmt.Errorf("hardening: rls-policy check: %w", err)
	}
	if len(noPolicy) > 0 {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("%d readable table(s) have row-level security enabled but NO policy, so they return no rows (default-deny); confirm this is intended: %s",
				len(noPolicy), strings.Join(noPolicy, ", ")))
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
