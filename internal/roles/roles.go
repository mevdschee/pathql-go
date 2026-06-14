// Package roles computes the DDL needed to synchronize PostgreSQL LOGIN roles
// with the pathql auth users table for the login_role RLS model.
//
// In that model each enabled user maps to a per-user LOGIN role named
// "<prefix><userID>" (e.g. "pathql_r_42"). The server itself never runs role
// DDL and never holds CREATEROLE: it only inspects pg_roles and the auth
// tables, then emits an ordered, idempotent DDL script that an out-of-band cron
// job applies as a privileged role. This package is the diff engine plus a thin
// catalog loader; it never executes the DDL it produces.
package roles

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/lib/pq"
)

// maxRoleNameBytes is the PostgreSQL identifier length limit (NAMEDATALEN-1).
// A managed role name must fit within it after the prefix is applied.
const maxRoleNameBytes = 63

// prefixRe validates a managed-role prefix. The prefix is the leading part of
// every generated role name, so it must itself be a valid lower-case
// identifier start. Role names are server-generated, but the prefix comes from
// config and is validated defensively.
var prefixRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// validatePrefix returns an error if prefix does not match ^[a-z_][a-z0-9_]*$.
// It is used both when deriving a single role name and when computing a diff,
// so an invalid prefix can never reach the emitted DDL.
func validatePrefix(prefix string) error {
	if !prefixRe.MatchString(prefix) {
		return fmt.Errorf("roles: invalid prefix %q: must match %s", prefix, prefixRe.String())
	}
	return nil
}

// RoleName derives the managed LOGIN role name for a user from the configured
// prefix and the user's integer primary key, as "<prefix><userID>". It is the
// single source of role names: names are never taken from request text. It
// returns an error if prefix is invalid or the resulting name exceeds 63 bytes,
// the PostgreSQL identifier length limit.
func RoleName(prefix string, userID int64) (string, error) {
	if err := validatePrefix(prefix); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s%d", prefix, userID)
	if len(name) > maxRoleNameBytes {
		return "", fmt.Errorf("roles: role name %q exceeds %d bytes", name, maxRoleNameBytes)
	}
	return name, nil
}

// Inputs is the hermetic, already-loaded snapshot Compute diffs. It carries no
// database handle so the diff logic is pure and fully testable offline.
type Inputs struct {
	// Prefix is the managed-role prefix, e.g. "pathql_r_". Only roles whose
	// name starts with it are ever touched.
	Prefix string
	// ReaderRole is the group role granting read access, e.g. "pathql_readers".
	// It is granted to every managed role and is itself never created or dropped.
	ReaderRole string
	// ExistingRoles are the current rolnames in the database that start with
	// Prefix.
	ExistingRoles []string
	// ExpectedUserIDs are the ids of the enabled users in the auth table; one
	// managed role is expected per id.
	ExpectedUserIDs []int64
	// ReaderMembers maps a managed role name to true when it already has
	// ReaderRole granted, so an unnecessary GRANT is not re-emitted.
	ReaderMembers map[string]bool
}

// Plan is the result of a diff: the role-level actions plus the exact, ordered
// SQL statements that realize them. DDL is what the cron job applies; the named
// slices are the same decisions in a form that is easy to report and assert on.
type Plan struct {
	// Create lists role names that are expected but do not yet exist.
	Create []string
	// GrantReader lists role names that need the reader grant: every created
	// role plus any existing role that lacks the membership.
	GrantReader []string
	// Drop lists managed-prefixed roles that exist but are no longer expected.
	Drop []string
	// DDL is the ordered, idempotent statement list: all creates, then all
	// grants, then all drops. Every identifier is quoted with pq.QuoteIdentifier.
	DDL []string
}

// Compute diffs the expected users against the existing roles and returns the
// plan plus the exact DDL to apply. It is pure and deterministic: outputs are
// sorted and depend only on Inputs.
//
// Safety rules it enforces:
//   - It only ever touches roles whose name starts with Prefix. An ExistingRole
//     that does not match the prefix is ignored entirely and can never appear in
//     Drop or DDL (the prefix guard).
//   - It never emits any statement for ReaderRole itself.
//   - An invalid Prefix is rejected before any DDL is produced.
//
// DDL forms (all identifiers quoted):
//
//	CREATE ROLE <role> LOGIN NOSUPERUSER NOCREATEROLE INHERIT;
//	GRANT <reader> TO <role>;
//	DROP ROLE IF EXISTS <role>;
func Compute(in Inputs) (Plan, error) {
	if err := validatePrefix(in.Prefix); err != nil {
		return Plan{}, err
	}

	// expectedNames is the set of role names we want to exist, derived from the
	// enabled user ids through RoleName so derivation and length validation are
	// shared with the rest of the package.
	expectedNames := make(map[string]bool, len(in.ExpectedUserIDs))
	for _, id := range in.ExpectedUserIDs {
		name, err := RoleName(in.Prefix, id)
		if err != nil {
			return Plan{}, err
		}
		expectedNames[name] = true
	}

	// existingSet holds only the existing roles that actually carry the managed
	// prefix. Anything else is unmanaged and is dropped from consideration here,
	// which is the core of the prefix guard.
	existingSet := make(map[string]bool, len(in.ExistingRoles))
	for _, name := range in.ExistingRoles {
		if !hasManagedPrefix(name, in.Prefix) {
			continue
		}
		existingSet[name] = true
	}

	plan := Plan{}

	// Create: expected names that do not exist yet.
	for name := range expectedNames {
		if !existingSet[name] {
			plan.Create = append(plan.Create, name)
		}
	}

	// GrantReader: every created role needs the grant; so does any existing
	// managed role that is expected but not yet a member of the reader role.
	for name := range expectedNames {
		if existingSet[name] && in.ReaderMembers[name] {
			continue // already exists with membership, nothing to do
		}
		plan.GrantReader = append(plan.GrantReader, name)
	}

	// Drop: managed roles that exist but are no longer expected.
	for name := range existingSet {
		if !expectedNames[name] {
			plan.Drop = append(plan.Drop, name)
		}
	}

	sort.Strings(plan.Create)
	sort.Strings(plan.GrantReader)
	sort.Strings(plan.Drop)

	plan.DDL = buildDDL(in.ReaderRole, plan)
	return plan, nil
}

// hasManagedPrefix reports whether name starts with prefix and is strictly
// longer than it, so the bare prefix itself is never treated as a managed role.
func hasManagedPrefix(name, prefix string) bool {
	return len(name) > len(prefix) && name[:len(prefix)] == prefix
}

// buildDDL renders the ordered statement list for a plan: all CREATE ROLE
// statements, then all GRANT statements, then all DROP ROLE statements last, so
// a created role is granted before any drop runs. Every identifier is quoted
// with pq.QuoteIdentifier.
func buildDDL(readerRole string, plan Plan) []string {
	ddl := make([]string, 0, len(plan.Create)+len(plan.GrantReader)+len(plan.Drop))
	for _, role := range plan.Create {
		ddl = append(ddl, fmt.Sprintf(
			"CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEROLE INHERIT;",
			pq.QuoteIdentifier(role),
		))
	}
	reader := pq.QuoteIdentifier(readerRole)
	for _, role := range plan.GrantReader {
		ddl = append(ddl, fmt.Sprintf(
			"GRANT %s TO %s;",
			reader, pq.QuoteIdentifier(role),
		))
	}
	for _, role := range plan.Drop {
		ddl = append(ddl, fmt.Sprintf(
			"DROP ROLE IF EXISTS %s;",
			pq.QuoteIdentifier(role),
		))
	}
	return ddl
}
